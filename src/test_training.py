"""Regresiones del pipeline: python -m unittest discover -s src -p 'test_*.py'."""
import csv
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import torch
from torch_geometric.loader import DataLoader

from model import PHPGuard
import phpgraph
import prepare_data
import train


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.vocab = phpgraph.vocab_state()
        phpgraph.load_vocab({"<unk>": 0})

    def tearDown(self):
        phpgraph.load_vocab(self.vocab)

    def prepare_fixture(self, root):
        mal, ben = root / "malicious", root / "benign"
        for split, repos in prepare_data.SPLIT_REPOS.items():
            for repo in repos:
                folder = (mal if repo in prepare_data.MALICIOUS_REPOS else ben) / repo
                folder.mkdir(parents=True)
                namespace = "namespace HeldOut; " if split != "train" else ""
                (folder / "sample.php").write_text(f"<?php {namespace}echo 'muestra inocua de {repo}';\n")
        ds_path = root / "graphs.pt"
        prepare_data.main(mal, ben, ds_path)
        return ds_path, torch.load(ds_path, weights_only=True)

    def test_frozen_vocabulary_and_repeatable_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path, ds = self.prepare_fixture(root)
            self.assertNotIn("namespace_definition", ds["vocab"])
            self.assertEqual(ds["vocab"]["<unk>"], 0)
            self.assertEqual(len(ds["graphs"]), 7)
            self.assertTrue(any((g["type"] == 0).any() for g in ds["graphs"] if g["split"] != "train"))
            with path.with_suffix('.manifest.csv').open() as f:
                self.assertEqual(len(list(csv.DictReader(f))), 7)
            prepare_data.main(root / "malicious", root / "benign", root / "repeat.pt")
            repeated = torch.load(root / "repeat.pt", weights_only=True)
            self.assertEqual(ds["vocab"], repeated["vocab"])
            for left, right in zip(ds["graphs"], repeated["graphs"], strict=True):
                for key in ("type", "sens", "flags", "edge_index", "lines", "ends"):
                    self.assertTrue(torch.equal(left[key], right[key]))
            with self.assertRaises(FileExistsError):
                prepare_data.main(root / "malicious", root / "benign", path)

    def test_partition_guards(self):
        rows = [dict(repo=repo, path=repo, y=int(repo in prepare_data.MALICIOUS_REPOS),
                     split=split, sha256=hashlib.sha256(repo.encode()).hexdigest())
                for split, repos in prepare_data.SPLIT_REPOS.items() for repo in repos]
        prepare_data.validate_graphs(rows)
        for key, value in (("sha256", rows[0]["sha256"]), ("split", "train"), ("y", 1)):
            invalid = [dict(r) for r in rows]
            invalid[-1][key] = value
            with self.assertRaises(ValueError):
                prepare_data.validate_graphs(invalid)
        with self.assertRaises(ValueError):
            prepare_data.validate_graphs([r for r in rows if r["split"] != "validation"])
        with self.assertRaises(ValueError):
            prepare_data.validate_graphs([r for r in rows if r["repo"] != "wordpress"])

    def test_graph_truncation(self):
        code = b"<?php echo 'muestra inocua';"
        complete = phpgraph.build_graph(code, grow_vocab=True)
        self.assertFalse(complete["truncated"])
        with patch.object(phpgraph, "MAX_NODES", complete["type"].numel()):
            self.assertFalse(phpgraph.build_graph(code)["truncated"])
        with patch.object(phpgraph, "MAX_NODES", 3):
            graph = phpgraph.build_graph(code)
            self.assertTrue(graph["truncated"])
            self.assertEqual(graph["type"].numel(), 3)
            self.assertTrue((graph["edge_index"] < 3).all())
        empty = phpgraph.build_graph(b"")
        self.assertEqual(empty["type"].numel(), 1)
        self.assertFalse(empty["truncated"])

    def test_training_selection_reload_and_reproducibility(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ds_path, ds = self.prepare_fixture(root)
            evaluate = train.evaluate
            checkpoints, predictions = [], []
            for run in ("first", "second"):
                calls = []

                def tied_validation(model, loader):
                    calls.append(loader)
                    metrics, ps = evaluate(model, loader)
                    if len(calls) <= 2:
                        metrics["f1"] = 0.75
                    return metrics, ps

                output = root / run / "phpguard.pt"
                with patch.object(train, "evaluate", side_effect=tied_validation):
                    result = train.main(ds_path, output, epochs=2)
                self.assertEqual(len(calls), 3)
                self.assertIs(calls[0], calls[1])
                self.assertIsNot(calls[1], calls[2])
                self.assertEqual(result["best_epoch"], 1)
                self.assertTrue(result["reload_verified"])
                self.assertEqual(result["test_evaluations"], 1)
                checkpoint = torch.load(output, weights_only=True)
                self.assertEqual(checkpoint["epoch"], 1)
                restored = PHPGuard(checkpoint["n_types"])
                restored.load_state_dict(checkpoint["state"])
                test_loader = DataLoader([train.to_data(g) for g in ds["graphs"] if g["split"] == "test"],
                                         batch_size=16, shuffle=False)
                metrics, probabilities = evaluate(restored, test_loader)
                self.assertEqual(metrics, result["final"])
                with (output.parent / "test_predictions.csv").open() as f:
                    saved = [float(row["probability"]) for row in csv.DictReader(f)]
                self.assertEqual(saved, probabilities)
                checkpoints.append(checkpoint)
                predictions.append(saved)
                with self.assertRaises(FileExistsError):
                    train.main(ds_path, output, epochs=2)
            self.assertEqual(predictions[0], predictions[1])
            for key, tensor in checkpoints[0]["state"].items():
                self.assertTrue(torch.equal(tensor, checkpoints[1]["state"][key]))


if __name__ == "__main__":
    unittest.main()
