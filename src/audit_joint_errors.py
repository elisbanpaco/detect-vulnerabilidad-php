"""Auditoría estática y ablaciones de características del checkpoint v2 congelado."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

import torch
import phpgraph
from audit_corpus import ROOT, sha256
from joint_model import JointPHPGuard
from semantic_features import SOURCE_IDS, inspect_code
from train_joint import read_graph


def main(dataset, run, out):
    if out.exists():
        raise FileExistsError(out)
    manifest_path = dataset / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    results = json.loads((run / "metrics.json").read_text())
    predictions = json.loads((run / "test_predictions.json").read_text())
    if sha256(manifest_path.read_bytes()) != results["manifest_sha256"]:
        raise ValueError("El manifiesto no corresponde a esta ejecución")
    if sha256((run / "best.pt").read_bytes()) != results["checkpoint_sha256"]:
        raise ValueError("El checkpoint no corresponde a las predicciones guardadas")
    by_id = {r["case_id"]: r for r in manifest["cases"]}
    checkpoint = torch.load(run / "best.pt", weights_only=True, map_location="cpu")
    model = JointPHPGuard(checkpoint["n_types"], **checkpoint["model_config"])
    model.load_state_dict(checkpoint["state"])
    model.eval()
    torch.set_num_threads(4)
    torch.use_deterministic_algorithms(True)
    profiles, fn, fp = [], [], []
    saved_predictions = {r["case_id"]: r for r in predictions}
    for i, row in enumerate(manifest["cases"], 1):
        prediction = saved_predictions.get(row["case_id"])
        if row["kind"] != "collected_malicious" and not (
                prediction and prediction["kind"] == "original" and prediction["predicted"]):
            continue
        code = (dataset / row["file_path"]).read_bytes()
        if sha256(code) != row["sha256"]:
            raise ValueError(f"Código modificado: {row['case_id']}")
        graph = read_graph(dataset, row)
        features = inspect_code(code)
        if features["source_kind"].numel() != graph["type"].numel():
            raise ValueError("AST no alineado con el grafo congelado")
        dynamic = [c for c in features["calls"] if c["kind"] != "named"]
        for call in dynamic:
            call["v2_dynamic_flag_at_call"] = float(graph["flags"][call["index"], 1])
        record = dict(case_id=row["case_id"], split=row["split"], kind=row["kind"], source_path=row["source_path"],
                      sha256=row["sha256"], n_nodes=row["n_nodes"],
                      sources=features["sources"], sensitive_nodes=int((graph["sens"] > 0).sum()),
                      dynamic_calls=dynamic, bitwise_operators=features["bitwise_operators"],
                      bare_constant_candidates=features["bare_constant_candidates"],
                      indirect_variables=features["indirect_variables"],
                      compatibility="unresolved; inspect definitions and intended PHP version")
        profiles.append(record)
        if prediction and prediction["label"] == 1 and prediction["predicted"] == 0:
            fn.append(dict(**record, probability=prediction["probability"],
                           review_status="assisted_structural_review; malicious intent and runtime compatibility not revalidated"))
        if prediction and prediction["kind"] == "original" and prediction["predicted"]:
            experiments = {"original": graph}
            for name, source_ids in (("without_globals_flag", {SOURCE_IDS['$GLOBALS']}),
                                     ("without_request_flags", {SOURCE_IDS[s] for s in ['$_GET','$_POST','$_REQUEST','$_COOKIE','$_FILES']})):
                variant = dict(graph, flags=graph["flags"].clone())
                mask = torch.tensor([int(x) in source_ids for x in features["source_kind"]], dtype=torch.bool)
                variant["flags"][mask, 0] = 0
                experiments[name] = variant
            variant = dict(graph, sens=graph["sens"].clone())
            variant["sens"][variant["sens"] == phpgraph.SENS_IDX['ini_set']] = 0
            experiments['without_ini_set_sensitive_id'] = variant
            scores = {}
            with torch.no_grad():
                for name, example in experiments.items():
                    scores[name] = torch.sigmoid(model(example)[0]).item()
            if abs(scores["original"] - prediction["probability"]) > 1e-6:
                raise ValueError("La reproducción de la predicción difiere del resultado guardado")
            text = code.decode('utf8', errors='replace').split('\n')
            fp.append(dict(**record, probability=prediction["probability"],
                           feature_ablations=scores,
                           ablation_caveat="Feature interventions only: not semantically equivalent PHP, not a new detector or an unbiased test.",
                           top_lines=[dict(**line, code=text[line['line'] - 1][:250]) for line in prediction['top_lines']]))
        if len(profiles) % 50 == 0:
            print(f"profiles {len(profiles)}", flush=True)
    summary = {}
    for split in ('train','validation','test'):
        selected = [r for r in profiles if r['split'] == split and r['kind'] == 'collected_malicious']
        summary[split] = dict(n=len(selected), with_dynamic_calls=sum(bool(r['dynamic_calls']) for r in selected),
                             with_at_least_5_bitwise_operators=sum(sum(r['bitwise_operators'].values()) >= 5 for r in selected),
                             without_visible_superglobals=sum(not r['sources'] for r in selected),
                             without_sensitive_nodes=sum(r['sensitive_nodes'] == 0 for r in selected))
    overall = dict(dataset_sha256=sha256(manifest_path.read_bytes()), checkpoint_sha256=results['checkpoint_sha256'],
                   profiles=summary, false_negatives=len(fn), original_false_positives=len(fp),
                   fn_with_dynamic_calls=sum(bool(r['dynamic_calls']) for r in fn),
                   fn_with_unmarked_dynamic_calls=sum(any(c['v2_dynamic_flag_at_call']==0 for c in r['dynamic_calls']) for r in fn),
                   fn_with_bare_constant_candidates=sum(bool(r['bare_constant_candidates']) for r in fn),
                   fn_without_visible_superglobals=sum(not r['sources'] for r in fn),
                   constants_policy="Candidates only; no PHP execution, no assumed legacy constant values, no automatic relabeling.",
                   php_sources=['https://www.php.net/manual/en/language.constants.syntax.php',
                                'https://www.php.net/manual/en/language.operators.bitwise.php'])
    out.mkdir(parents=True)
    for name, value in [('profiles',profiles),('false_negatives',fn),('false_positives',fp),('summary',overall)]:
        (out / f'{name}.json').write_text(json.dumps(value,indent=2,allow_nan=False)+'\n')
    print(json.dumps(overall,indent=2),flush=True)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=ROOT/'dataset/processed/joint')
    parser.add_argument('--run',type=Path,default=ROOT/'artifacts/joint')
    parser.add_argument('--out',type=Path,default=ROOT/'artifacts/joint_error_audit')
    args=parser.parse_args()
    main(args.dataset,args.run,args.out)
