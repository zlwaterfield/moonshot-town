from fastapi import FastAPI, Request, HTTPException, status
import hmac
import hashlib
import json
import requests

app = FastAPI()
github_secret = b'{GITHUB_WEBHOOK_SECRET}'
slack_webhook_url = 'your_slack_webhook_url'

@app.post("/webhooks/github")
async def handle_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get('X-Hub-Signature')

    if not is_valid_signature(signature, body):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid signature")

    payload = await request.json()
    process_payload(payload)
    return {"message": "Webhook processed successfully"}

def is_valid_signature(signature, data):
    if not signature:
        return False
    sha_name, signature = signature.split('=')
    if sha_name != 'sha1':
        return False
    mac = hmac.new(github_secret, msg=data, digestmod=hashlib.sha1)
    return hmac.compare_digest(mac.hexdigest(), signature)

def process_payload(payload):
    keywords = ["new", "comment"]  # Add your keywords here
    message = ""

    # Check for new pull requests
    if payload.get("pull_request") and payload.get("action") in ["opened", "reopened"]:
        title = payload["pull_request"]["title"]
        if any(keyword in title for keyword in keywords):
            message += f"New pull request: {title}\n"

    # Check for pull request comments/reviews
    elif payload.get("comment") and "pull_request" in payload["comment"]["html_url"]:
        comment = payload["comment"]["body"]
        if any(keyword in comment for keyword in keywords):
            message += f"New pull request comment: {comment}\n"

    # Check for new issues
    elif payload.get("issue") and payload.get("action") in ["opened", "reopened"]:
        title = payload["issue"]["title"]
        if any(keyword in title for keyword in keywords):
            message += f"New issue: {title}\n"

    # Check for issue comments
    elif payload.get("comment") and "issues" in payload["comment"]["html_url"]:
        comment = payload["comment"]["body"]
        if any(keyword in comment for keyword in keywords):
            message += f"New issue comment: {comment}\n"

    # Check for new discussions (assuming payload structure is similar to issues)
    elif payload.get("discussion") and payload.get("action") in ["opened", "reopened"]:
        title = payload["discussion"]["title"]
        if any(keyword in title for keyword in keywords):
            message += f"New discussion: {title}\n"

    # Check for discussion comments (assuming payload structure is similar to issue comments)
    elif payload.get("comment") and "discussions" in payload["comment"]["html_url"]:
        comment = payload["comment"]["body"]
        if any(keyword in comment for keyword in keywords):
            message += f"New discussion comment: {comment}\n"

    if message:
        post_message_to_slack(message)


def post_message_to_slack(message):
    url = 'https://slack.com/api/chat.postMessage'
    headers = {
        'Authorization': 'Bearer {SLACK_BOT_TOKEN}',
        'Content-Type': 'application/json'
    }
    payload = {
        'channel': 'C01BUH5AWCF',
        'text': message
    }
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200 and response.json()['ok']:
        print('Message posted successfully')
    else:
        print('Failed to post message')

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
