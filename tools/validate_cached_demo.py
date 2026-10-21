"""Execute the replay in a fresh kernel and empty directory, with networking blocked."""
import ast
import base64
import io
import json
from pathlib import Path
import sys
import tempfile
import zipfile

import nbformat
from nbclient import NotebookClient


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "notebooks" / "milestone_colab_cached_video.ipynb"
nb = nbformat.read(SOURCE, as_version=4)
nbformat.validate(nb)
allowed = {"base64", "hashlib", "io", "json", "types", "zipfile", "pandas", "IPython"}
for cell in nb.cells:
    if cell.cell_type != "code":
        continue
    for node in ast.walk(ast.parse(cell.source)):
        if isinstance(node, ast.Import):
            assert all(alias.name.split(".")[0] in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module.split(".")[0] in allowed
setup = next(cell for cell in nb.cells if cell.cell_type == "code")
tree = ast.parse(setup.source)
assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "payload_bytes" for t in node.targets))
payload = base64.b64decode(ast.literal_eval(assignment.value.args[0]))
with zipfile.ZipFile(io.BytesIO(payload)) as package:
    assert set(package.namelist()) == {"frozen_results.json", "cached_analysis.py"}
    source = package.read("cached_analysis.py").decode("utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            assert all(alias.name == "math" for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module == "collections"
    frozen = json.loads(package.read("frozen_results.json"))
    assert len(frozen["cache"]) == 1436 and not frozen["ledger"]

# This guard is only in the validation kernel. The shipped notebook itself needs
# no socket access. ZMQ kernel messaging is not Python socket networking.
guard = nbformat.v4.new_code_cell('''import socket
def deny_network(*args, **kwargs):
    raise RuntimeError("Network/model calls disabled during cached replay validation")
socket.create_connection = deny_network
socket.socket.connect = deny_network
socket.socket.connect_ex = deny_network
''')
nb.cells.insert(0, guard)
with tempfile.TemporaryDirectory(prefix="14795-replay-validation-") as empty:
    client = NotebookClient(nb, timeout=180, kernel_name="python3",
                            resources={"metadata": {"path": empty}})
    client.create_kernel_manager()
    client.km.kernel_spec.argv = [sys.executable, "-m", "ipykernel_launcher", "-f", "{connection_file}"]
    client.execute()
    nb.cells.pop(0)
    for i, cell in enumerate(nb.cells):
        assert not any(out.output_type == "error" for out in cell.get("outputs", [])), i
    # Preserve an executed, inspectable artifact without changing its code cells.
    dest = ROOT / "notebooks" / "milestone_colab_cached_video_executed.ipynb"
    nbformat.write(nb, dest)
    record = {"validated": True, "code_cells_executed": sum(c.cell_type == "code" for c in nb.cells),
              "empty_working_directory": True, "network_blocked": True,
              "model_calls": 0, "colab_runtime_verified": False,
              "note": "Executed in a fresh local Jupyter kernel using saved results only; Colab UI execution not automated.",
              "executed_notebook": str(dest)}
    (ROOT / "results" / "cached_demo_validation.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(record, indent=2))
