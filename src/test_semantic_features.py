import unittest

import torch
import phpgraph
from audit_corpus import graph_hash
from joint_graph import build_joint_graph
from semantic_features import SOURCE_IDS, build_semantic_graph, inspect_code


class SemanticFeatureTests(unittest.TestCase):
    def setUp(self):
        self.vocab=phpgraph.vocab_state()
        phpgraph.load_vocab({'<unk>':0})

    def tearDown(self):
        phpgraph.load_vocab(self.vocab)

    def test_source_information_loss_and_explicit_identity(self):
        external=b"<?php $x=$_POST['a']; echo $x;"
        internal=b"<?php $x=$GLOBALS['a']; echo $x;"
        left=build_joint_graph(external,True);right=build_joint_graph(internal,True)
        self.assertEqual(graph_hash(left),graph_hash(right))
        a=build_semantic_graph(external);b=build_semantic_graph(internal)
        self.assertFalse(torch.equal(a['source_kind'],b['source_kind']))
        self.assertIn(SOURCE_IDS['$_POST'],a['source_kind'].tolist())
        self.assertIn(SOURCE_IDS['$GLOBALS'],b['source_kind'].tolist())

    def test_variable_literal_and_named_calls(self):
        code=b"<?php $f='strlen'; $f('x'); strlen('x'); ('str'.'len')('x');"
        old=build_joint_graph(code,True)
        features=inspect_code(code)
        variable=next(c for c in features['calls'] if c['kind']=='variable')
        self.assertEqual(old['flags'][variable['index'],1].item(),0)
        self.assertEqual(features['call_kind'][variable['index']].item(),2)
        self.assertEqual(len(features['source_kind']),old['type'].numel())
        self.assertIn('named',{c['kind'] for c in features['calls']})
        self.assertIn('expression',{c['kind'] for c in features['calls']})

    def test_constants_are_candidates_not_evaluated(self):
        code=b"<?php $x='A'^UNKNOWN; $f($x);"
        features=inspect_code(code)
        self.assertEqual(features['bitwise_operators']['^'],1)
        self.assertIn('UNKNOWN',features['bare_constant_candidates'])
        self.assertNotIn('resolved_values',features)


if __name__=='__main__':
    unittest.main()
