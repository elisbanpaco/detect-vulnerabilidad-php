"""CLI distribuible: 0 sin indicios, 1 sospechoso, 2 no analizable; nunca ejecuta PHP."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parent.parent
MODEL = ROOT / "models/joint-v2.pt"
MANIFEST = ROOT / "models/manifest.json"


def scan_file(path):
    if not path.is_file():
        raise ValueError(f"No es un archivo regular existente: {path}")
    with path.open("rb") as stream:
        code = stream.read(200_001)
    if len(code) > 200_000:
        raise ValueError("El archivo supera 200000 bytes; no se recorta ni se clasifica")
    if b"<?" not in code:
        raise ValueError("No se encontró una etiqueta de apertura PHP")
    manifest = json.loads(MANIFEST.read_text(encoding="utf8"))
    with MODEL.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != manifest["sha256"]:
        raise ValueError("El SHA-256 del modelo no coincide con el manifiesto distribuido")

    import torch
    from predict_joint import analyze_joint

    torch.set_num_threads(4)
    result = analyze_joint(code, MODEL)
    if result["parse_error"]:
        raise ValueError("El parser detectó errores de sintaxis; no se emite una clasificación")
    result["verdict"] = "SOSPECHOSO" if result["probability"] > .5 else "SIN_INDICIOS"
    result.update(model=manifest["id"], model_sha256=digest)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path, help="Archivo PHP local, de hasta 200000 bytes")
    args = parser.parse_args(argv)
    try:
        result = scan_file(args.file)
    except Exception as error:
        print(json.dumps(dict(verdict="NO_ANALIZABLE", error=str(error)), ensure_ascii=False), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False))
    return int(result["verdict"] == "SOSPECHOSO")


if __name__ == "__main__":
    sys.exit(main())
