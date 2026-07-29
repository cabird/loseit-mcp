import json
p = r"C:\Users\cbird\AppData\Local\Temp\lose-it\src\lose_it\core\_schemas.json"
d = json.load(open(p, encoding="utf-8"))["schemas"]
for k, v in d.items():
    if "Weight" in k:
        print("==", k)
        print(json.dumps(v, indent=2)[:900])
        print()
