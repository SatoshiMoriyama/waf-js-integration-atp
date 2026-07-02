import json


def handler(event, context):
    # 検証ロジックは持たず、常に成功を返すモック
    try:
        payload = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        payload = {}

    username = payload.get("username", "unknown")

    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json",
            # Amplify Hosting(別オリジン)からのfetchを許可するためCORSヘッダーを付与
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps({"message": f"login ok (mock) for {username}"}),
    }
