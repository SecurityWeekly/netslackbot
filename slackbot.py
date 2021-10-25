import requests
import json

# importing `config.py` to access its variables
import config

#
# Very simple function to post a message to a Slack channel
#
def post_message_to_slack(text, blocks=None):
    post_request_results = ''

    try:
        post_request_results = requests.post('https://slack.com/api/chat.postMessage', {
        'token': config.SLACK_TOKEN,
        'channel': config.SLACK_CHANNEL,
        'text': text,
        'icon_emoji': config.SLACK_EMOJI,
        'username': config.SLACK_EMOJI,
        'blocks': json.dumps(blocks) if blocks else None
        }).json()
    except Exception as e:
        print('Exception error when posting to Slack: '+str(e))

    return post_request_results
