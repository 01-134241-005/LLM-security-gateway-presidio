# test_imports.py
print("Testing imports...")
print("=" * 40)

try:
    import spacy
    print(f"✅ spacy {spacy.__version__} imported")
except ImportError as e:
    print(f"❌ spacy failed: {e}")

try:
    from presidio_analyzer import AnalyzerEngine
    print("✅ presidio_analyzer imported")
except ImportError as e:
    print(f"❌ presidio_analyzer failed: {e}")

try:
    from presidio_anonymizer import AnonymizerEngine
    print("✅ presidio_anonymizer imported")
except ImportError as e:
    print(f"❌ presidio_anonymizer failed: {e}")

try:
    import yaml
    print(f"✅ pyyaml {yaml.__version__} imported")
except ImportError as e:
    print(f"❌ pyyaml failed: {e}")

try:
    import pandas as pd
    print(f"✅ pandas {pd.__version__} imported")
except ImportError as e:
    print(f"❌ pandas failed: {e}")

try:
    from tabulate import tabulate
    print("✅ tabulate imported")
except ImportError as e:
    print(f"❌ tabulate failed: {e}")

print("\n" + "=" * 40)
print("Testing spaCy model...")
try:
    nlp = spacy.load("en_core_web_lg")
    doc = nlp("Test sentence")
    print(f"✅ spaCy model loaded successfully! Found {len(doc)} tokens")
except Exception as e:
    print(f"❌ spaCy model failed: {e}")

print("\n" + "=" * 40)
print("All tests completed!")