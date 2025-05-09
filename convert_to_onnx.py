#!/usr/bin/env python3
# convert_xgb_json_to_onnx.py – onnxmltools flavour, robust for no names

import sys, onnx, xgboost as xgb
from onnxmltools.convert import convert_xgboost
from skl2onnx.common.data_types import FloatTensorType

def main(in_json: str, out_onnx: str):
    # 1 ▸ load booster
    booster = xgb.Booster()
    booster.load_model(in_json)

    # 2 ▸ how many columns does the model expect?
    n_features = booster.num_features()              # << safe, always int

    # 3 ▸ if names missing or wrong length, create f0…fN
    if not booster.feature_names or len(booster.feature_names) != n_features:
        booster.feature_names = [f"f{i}" for i in range(n_features)]

    # 4 ▸ ONNX conversion
    init = [("input", FloatTensorType([None, n_features]))]
    opset = min(15, onnx.defs.onnx_opset_version())  # keep ≤ your onnx build
    onx   = convert_xgboost(booster, initial_types=init, target_opset=opset)

    onnx.save_model(onx, out_onnx)
    print(f"✅  wrote {out_onnx}  (opset {opset}, {n_features} features)")

# -------------------------------------------------------------------------
if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python convert_xgb_json_to_onnx.py <in.json> <out.onnx>")
    main(sys.argv[1], sys.argv[2])
