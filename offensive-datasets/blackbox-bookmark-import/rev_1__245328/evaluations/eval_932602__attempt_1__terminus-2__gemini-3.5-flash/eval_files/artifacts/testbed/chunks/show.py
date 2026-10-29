import sys, json
data = json.load(sys.stdin)
for b in data.get('bookmarks', [])[:10]:
    print(f"{b['id']}: url={b['content']['url']}, status={b['content']['crawlStatus']}")
