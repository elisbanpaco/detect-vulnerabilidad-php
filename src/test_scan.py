"""Contrato del CLI y puente PHP, sin evaluar nuevamente el corpus de prueba."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import scan


class ScanTests(unittest.TestCase):
    def test_verdicts_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample.php"
            source.write_bytes(b"<?php echo 123;")
            for probability, verdict, expected in ((.5, "SIN_INDICIOS", 0), (.9, "SOSPECHOSO", 1)):
                output = io.StringIO()
                with patch("predict_joint.analyze_joint", return_value=dict(probability=probability, parse_error=False)), redirect_stdout(output):
                    self.assertEqual(scan.main([str(source)]), expected)
                result = json.loads(output.getvalue())
                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(result["model_sha256"], json.loads(scan.MANIFEST.read_text())["sha256"])

    def test_unanalyzable_inputs_and_checkpoint_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "sample.php"
            for content in (b"", b"plain text", b"<?php " + b"x" * 200_000):
                source.write_bytes(content)
                output = io.StringIO()
                with redirect_stderr(output):
                    self.assertEqual(scan.main([str(source)]), 2)
                self.assertEqual(json.loads(output.getvalue())["verdict"], "NO_ANALIZABLE")
            with self.assertRaises(ValueError):
                scan.scan_file(Path(tmp) / "missing.php")
            source.write_bytes(b"<?php echo 123;")
            corrupt = Path(tmp) / "bad.pt"
            corrupt.write_bytes(b"invalid checkpoint")
            with patch.object(scan, "MODEL", corrupt), self.assertRaisesRegex(ValueError, "SHA-256"):
                scan.scan_file(source)
            with patch("predict_joint.analyze_joint", return_value=dict(probability=.1, parse_error=True)), self.assertRaisesRegex(ValueError, "sintaxis"):
                scan.scan_file(source)
            with patch("predict_joint.analyze_joint", side_effect=ImportError("missing dependency")), redirect_stderr(io.StringIO()):
                self.assertEqual(scan.main([str(source)]), 2)

    @unittest.skipUnless(shutil.which("php") and os.name == "posix", "requiere PHP CLI y POSIX")
    def test_php_passes_literal_arguments_and_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            interpreter = Path(tmp) / "fake python"
            interpreter.write_text(f"#!{sys.executable}\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\nsys.exit(int(sys.argv[-1]))\n")
            interpreter.chmod(0o755)
            marker = Path(tmp) / "unexpected"
            argument = f"sample with spaces; touch {marker}; $(echo unsafe).php"
            for status in (0, 1, 2, 127):
                result = subprocess.run(["php", str(scan.ROOT / "bin/phpguard"), argument, str(status)],
                                        env=dict(os.environ, PHPGUARD_PYTHON=str(interpreter)),
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, status if status in (0, 1, 2) else 2)
                self.assertEqual(json.loads(result.stdout)[1], argument)
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
