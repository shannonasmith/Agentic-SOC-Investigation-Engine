#!/bin/bash

echo ""
echo "======================================"
echo "=== Ingesting Zeek Logs ==="
echo "======================================"
echo ""

python -m pipeline.ingest_logs --source zeek --path data/sample/

sleep 1

echo ""
echo "======================================"
echo "=== Running ATT&CK Mapping ==="
echo "======================================"
echo ""

python -m pipeline.analyze_alerts --input output/normalized_zeek_alerts.json > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "Analysis complete"
else
    echo "Analysis failed"
    exit 1
fi

sleep 1

echo ""
echo "======================================"
echo "=== FINAL DETECTION ==="
echo "======================================"
echo ""

jq -r '.[3] | "Technique: \(.matches[0].technique_id) - \(.matches[0].name) | Confidence: \(.matches[0].confidence)%"' output/mapped_alerts.json

echo ""
echo "======================================"
echo "=== Demo Complete ==="
echo "======================================"
echo ""
