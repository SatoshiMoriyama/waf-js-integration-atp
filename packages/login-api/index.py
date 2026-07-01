import json


def handler(event, context):
    # 検証ロジックは持たず、常に成功を返すモック
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"message": "login ok (mock)"}),
    }
