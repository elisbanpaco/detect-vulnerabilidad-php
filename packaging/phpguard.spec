from importlib.metadata import distributions
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

root = Path(SPECPATH).parent
data = [(str(root / "models/joint-v2.pt"), "models"),
        (str(root / "models/manifest.json"), "models"),
        (str(root / "LICENSE"), "licenses/phpguard")]
data += collect_data_files("torch_geometric", includes=["**/*.jinja"])
for distribution in distributions():
    for file in distribution.files or []:
        if any(part.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT")) for part in file.parts):
            source = Path(distribution.locate_file(file))
            if source.is_file():
                data.append((str(source), "licenses/" + distribution.metadata["Name"] + "/" + str(file.parent)))

analysis = Analysis(
    [str(root / "src/scan.py")],
    pathex=[str(root / "src")],
    datas=data,
    excludes=["flask", "tkinter", "matplotlib", "tensorboard"],
    module_collection_mode={"torch_geometric": "pyz+py"},
)
archive = PYZ(analysis.pure)
executable = EXE(archive, analysis.scripts, [], exclude_binaries=True,
                 name="phpguard-engine", console=True, strip=False, upx=False)
bundle = COLLECT(executable, analysis.binaries, analysis.datas,
                 name="phpguard-engine", strip=False, upx=False)
