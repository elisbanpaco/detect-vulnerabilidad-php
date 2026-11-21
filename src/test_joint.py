"""Comprobaciones del modelo conjunto; el entrenamiento de prueba solo usa PHP sintético."""
import json
import logging
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import torch
import torch.nn.functional as F

from audit_corpus import sha256
from joint_graph import GRAPH_VERSION, build_joint_graph
from joint_model import JointPHPGuard
from predict_joint import analyze_joint
from prepare_joint import source_hashes
import phpgraph
import train_joint


class JointTests(unittest.TestCase):
    def setUp(self):
        self.vocab = phpgraph.vocab_state()
        phpgraph.load_vocab({"<unk>": 0})
        torch.set_num_threads(4)

    def tearDown(self):
        phpgraph.load_vocab(self.vocab)

    def test_complete_tail_coverage(self):
        code = b"<?php\n" + b"echo 'safe';\n" * 700 + b"$x = $_POST['q'];\n\\system($x);\n"
        old = phpgraph.build_graph(code, grow_vocab=True)
        graph = build_joint_graph(code, grow_vocab=True)
        self.assertTrue(old["truncated"])
        self.assertFalse(graph["truncated"])
        self.assertGreater(graph["type"].numel(), 2500)
        self.assertIn(703, graph["lines"].tolist())
        self.assertGreater(graph["flow_edges"], 0)

    def test_lexical_definitions_and_scope_isolation(self):
        code = b"<?php\n$x = $_POST['q'];\n\\system($x);\nfunction f(){ \\system($x); }\n$x = 'date';\n\\system($x);\n"
        graph = build_joint_graph(code, grow_vocab=True)
        vocab = phpgraph.vocab_state()

        def index(kind, line):
            return next(i for i, (t, ln) in enumerate(zip(graph["type"].tolist(), graph["lines"].tolist()))
                        if t == vocab[kind] and ln == line)

        edges = set(map(tuple, graph["edge_index"].t().tolist()))
        first, second = index('assignment_expression', 2), index('assignment_expression', 5)
        self.assertIn((first, index('function_call_expression', 3)), edges)
        self.assertIn((second, index('function_call_expression', 6)), edges)
        self.assertNotIn((first, index('function_call_expression', 6)), edges)
        self.assertNotIn((first, index('function_call_expression', 4)), edges)

    def test_line_loss_and_checkpoint_inference(self):
        code = b"<?php\n$x=$_POST['q'];\n\\system($x);\n"
        graph = build_joint_graph(code, grow_vocab=True)
        model = JointPHPGuard(len(phpgraph.vocab_state()))
        file_logit, logits, lines = model(graph)
        self.assertTrue(torch.equal(file_logit, logits.max().reshape(1)))
        targets = torch.tensor([float(line in [2, 3]) for line in lines.tolist()])
        loss = F.binary_cross_entropy_with_logits(file_logit, torch.ones(1)) + F.binary_cross_entropy_with_logits(logits, targets)
        loss.backward()
        self.assertTrue(all(p.grad is None or torch.isfinite(p.grad).all() for p in model.parameters()))
        self.assertGreater(model.line_head.weight.grad.abs().sum().item(), 0)
        model.eval()
        with torch.no_grad():
            expected = torch.sigmoid(model(graph)[0]).item()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'model.pt'
            torch.save(dict(version=2, graph_version=GRAPH_VERSION, state=model.state_dict(),
                            vocab=phpgraph.vocab_state(), n_types=len(phpgraph.vocab_state()),
                            model_config=dict(hid=64, heads=4, layers=3, drop=.2)), path)
            result = analyze_joint(code, path)
            self.assertEqual(result['probability'], expected)
            self.assertFalse(result['truncated'])
            self.assertTrue(any(r['line'] == 3 for r in result['top_lines']))

    def test_training_smoke_and_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'data'
            folder.mkdir()
            cases = []
            for split_index, split in enumerate(['train', 'validation', 'test']):
                prefix = b'<?php\n' + b'echo 1;\n' * (split_index + 1)
                source_line = prefix.count(b'\n') + 1
                for label in (0, 1):
                    code = prefix + (b"$x=$_POST['q'];\n" if label else b"$x='date';\n") + b'\\system($x);\n'
                    graph = build_joint_graph(code, grow_vocab=split == 'train')
                    gold = [source_line, source_line + 1] if label else []
                    ids = torch.unique(graph['lines'], sorted=True)
                    graph['line_target'] = torch.tensor([float(line in gold) for line in ids.tolist()])
                    path = folder / f'{split}_{label}.pt'
                    torch.save(graph, path)
                    cases.append(dict(case_id=path.stem, split=split, group_id=split, label=label,
                                      graph_path=path.name, graph_file_sha256=sha256(path.read_bytes()),
                                      line_supervised=True, malicious_lines=gold, represented_lines=len(ids),
                                      positive_lines=len(gold), kind='malicious' if label else 'constant_control',
                                      pattern='command', position='middle'))
            manifest = dict(version=2, graph_version=GRAPH_VERSION, vocab=phpgraph.vocab_state(),
                            source_sha256=source_hashes(), cases=cases, caveats=['Synthetic smoke only'])
            (folder / 'manifest.json').write_text(json.dumps(manifest))
            evaluator = train_joint.evaluate_joint
            calls = []

            def tied(model, data, rows):
                calls.append(rows)
                metrics, predictions = evaluator(model, data, rows)
                if len(calls) <= 2:
                    metrics['selection_score'] = .5
                return metrics, predictions

            out = Path(tmp) / 'smoke'
            with patch.object(train_joint, 'evaluate_joint', side_effect=tied):
                result = train_joint.main(folder, out, epochs=2)
            self.assertEqual(len(calls), 3)
            self.assertIs(calls[0], calls[1])
            self.assertIsNot(calls[1], calls[2])
            self.assertEqual(result['best_epoch'], 1)
            self.assertEqual(result['test_evaluations'], 1)
            self.assertEqual(len(json.loads((out / 'test_predictions.json').read_text())), 2)
            checkpoint = torch.load(out / 'best.pt', weights_only=True)
            restored = JointPHPGuard(checkpoint['n_types'], **checkpoint['model_config'])
            restored.load_state_dict(checkpoint['state'])
            metrics, predictions = evaluator(restored, folder, [r for r in cases if r['split'] == 'test'])
            self.assertEqual(metrics, result['final'])
            self.assertEqual(predictions, json.loads((out / 'test_predictions.json').read_text()))
            with self.assertRaises(FileExistsError):
                train_joint.main(folder, out)
            changed = dict(manifest)
            changed['source_sha256'] = {}
            (folder / 'manifest.json').write_text(json.dumps(changed))
            with self.assertRaises(ValueError):
                train_joint.main(folder, Path(tmp) / 'invalid')
            logging.shutdown()


if __name__ == '__main__':
    unittest.main()
