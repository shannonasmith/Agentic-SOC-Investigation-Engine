from modules.soar.soar_engine import generate_soar_output

sample_techniques = [
    {"tactics": ["lateral-movement"]}
]

result = generate_soar_output(
    alert={},
    mapped_techniques=sample_techniques,
    severity="high",
    confidence=0.9
)

print(result)
