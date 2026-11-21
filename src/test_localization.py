"""Regresiones del benchmark y métricas; todos los ejemplos se leen como datos."""
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from sklearn.metrics import roc_auc_score
import torch
from torch_geometric.data import Batch

from audit_corpus import graph_hash, group_rows, sha256, token_hash
from build_localization import PATTERNS, insert, insertion_points, payload
from evaluate_localization import bag_features, localization_metrics, ranked_lines, summary_statistics
from model import PHPGuard, node_saliency
import phpgraph
from train import to_data


class LocalizationTests(unittest.TestCase):
    def setUp(self):
        self.vocab = phpgraph.vocab_state()
        phpgraph.load_vocab({"<unk>": 0})
        torch.set_num_threads(4)

    def tearDown(self):
        phpgraph.load_vocab(self.vocab)

    def test_normalization_is_not_semantic_identity(self):
        left = b"<?php $a = 'one'; system($a);"
        renamed = b"<?php $b = 'two'; system($b);"
        safe = b"<?php $b = 'two'; strlen($b);"
        a, b, c = [phpgraph.build_graph(code, grow_vocab=True) for code in (left, renamed, safe)]
        self.assertNotEqual(sha256(left), sha256(renamed))
        self.assertEqual(graph_hash(a), graph_hash(b))
        self.assertEqual(token_hash(left), token_hash(safe))
        self.assertNotEqual(graph_hash(a), graph_hash(c))
        rows = [dict(path='a', sha256='a', graph_sha256='same', tokens_sha256='x', split='train', label=1),
                dict(path='b', sha256='b', graph_sha256='same', tokens_sha256='y', split='test', label=1),
                dict(path='c', sha256='c', graph_sha256='other', tokens_sha256='y', split='test', label=0)]
        groups = group_rows(rows)
        self.assertTrue(all(r['excluded_from_benchmark'] for r in rows))
        self.assertTrue(all(r['group_has_label_conflict'] for r in rows))
        self.assertEqual(len({r['group_id'] for r in rows}), 1)
        self.assertIn('normalization_candidate_not_confirmed_clone_or_family', {g['assessment'] for g in groups})

    def test_insertion_offsets_reversibility_and_paired_controls(self):
        for namespace in (b'namespace Demo;', b'namespace Demo {'):
            suffix = b'\n}' if namespace.endswith(b'{') else b''
            code = b"<?php declare(strict_types=1);\n" + namespace + b"\nfunction task() {\n $x = 'caf\xc3\xa9';\n $y = 2;\n return $y;\n}\necho task();" + suffix
            offsets = insertion_points(code)
            self.assertEqual(len(set(offsets)), 3)
            self.assertTrue(all(offset > code.index(b'declare(strict_types=1);') for offset in offsets))
            for pattern in PATTERNS:
                for offset in offsets:
                    positive, local = payload(pattern, True, 'abc123')
                    negative, _ = payload(pattern, False, 'abc123')
                    self.assertEqual(positive.splitlines()[0], negative.splitlines()[0])
                    for block, label in ((positive, 1), (negative, 0)):
                        result, lines, length = insert(code, offset, block, local)
                        self.assertEqual(result[:offset] + result[offset + length:], code)
                        self.assertFalse(phpgraph._parser.parse(result).root_node.has_error)
                        text = result.split(b'\n')
                        self.assertIn(b'$v_abc123 = ', text[lines[0] - 1])
                        self.assertIn(b'$v_abc123', text[lines[1] - 1])
                        if label == 1:
                            self.assertIn(b"$_POST['abc123']", text[lines[0] - 1])
                        else:
                            self.assertNotIn(b'$_POST', text[lines[0] - 1])
        html = b'<?php echo 1; ?>\n<html>outside PHP</html>'
        with self.assertRaises(ValueError):
            insert(html, len(html), b'system($_POST["x"]);', [0])

    def test_saliency_repeats_without_parameter_gradients(self):
        graph = phpgraph.build_graph(b"<?php echo 'test';", grow_vocab=True)
        graph['y'] = 0
        data = Batch.from_data_list([to_data(graph)])
        model = PHPGuard(len(phpgraph.vocab_state()))
        before = {key: value.clone() for key, value in model.state_dict().items()}
        scores, probability = node_saliency(model, data)
        again, repeated_probability = node_saliency(model, data)
        torch.testing.assert_close(scores, again, rtol=0, atol=0)
        self.assertEqual(probability, repeated_probability)
        self.assertTrue(all(p.grad is None for p in model.parameters()))
        for key, value in model.state_dict().items():
            self.assertTrue(torch.equal(before[key], value))
        self.assertEqual(bag_features(graph, len(phpgraph.vocab_state())).shape,
                         (len(phpgraph.vocab_state()) + phpgraph.N_SENS + 5,))

    def test_explicit_checkpoint_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / 'first.pt'
            second = Path(tmp) / 'second.pt'
            for path in (first, second):
                model = PHPGuard(1)
                torch.save(dict(state=model.state_dict(), n_types=1, vocab={'<unk>': 0}), path)
                with patch.dict(os.environ, {'PHPGUARD_CHECKPOINT': str(path)}):
                    namespace = runpy.run_path(str(Path(__file__).with_name('detect.py')))
                self.assertEqual(namespace['CHECKPOINT_PATH'], str(path))
                self.assertEqual(namespace['CHECKPOINT_SHA256'], sha256(path.read_bytes()))

    def test_localization_and_cluster_bootstrap(self):
        self.assertEqual(ranked_lines([0, 0, 0]), [])
        self.assertEqual(ranked_lines([2, 2, 0]), [1, 2])
        self.assertEqual(localization_metrics([2, 3], [2, 7, 8])['iou@5'], 0.25)
        rows = []
        for i, (label, score) in enumerate(((0, .2), (1, .6), (0, .6), (1, .9))):
            rows.append(dict(label=label, score=score, predicted=int(score > .5), continuous_score=True,
                             group_id=str(i // 2), annotation_status='complete_controlled',
                             malicious_lines=[99] if label else [], ranking=[1, 2, 3]))
        report = summary_statistics(rows, bootstrap=1000)
        self.assertEqual(report['metrics']['auc'], roc_auc_score([0, 1, 0, 1], [.2, .6, .6, .9]))
        self.assertEqual(report['metrics']['f1'], .8)
        self.assertEqual(report['metrics']['e2e.hit@3'], 0)
        self.assertEqual(report, summary_statistics(rows, bootstrap=1000))
        self.assertEqual(report['groups'], 2)
        missed = dict(rows[1], predicted=0, score=.1, ranking=[99], group_id='missed')
        partial = dict(rows[3], annotation_status='partial_assisted', ranking=[99], group_id='partial')
        ambiguous = dict(rows[0], annotation_status='ambiguous')
        result = summary_statistics([missed, partial, ambiguous], bootstrap=40)
        self.assertEqual(result['n'], 2)
        self.assertEqual(result['ambiguous_excluded'], 1)
        self.assertEqual(result['metrics']['e2e.hit@3'], 0)
        self.assertIsNone(result['metrics']['conditional.hit@3'])
        self.assertEqual(result['metrics']['partial.hit@1'], 1)
        self.assertNotIn('partial.iou@5', result['metrics'])
        self.assertIsNone(result['metrics']['precision'])
        self.assertNotIn('auc', result['metrics'])


if __name__ == '__main__':
    unittest.main()
