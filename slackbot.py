import requests
#
# Enter your Slack tokens and other parameters for your Slack channel here:
#
SLACK_TOKEN = ''
SLACK_CHANNEL = ''
SLACK_EMOJI = ''
SLACK_USERNAME = ''

#
# Very simple function to post a message to a Slack channel
#
def post_message_to_slack(text, blocks=None):
    post_request_results = ''

    try:
        post_request_results = requests.post('https://slack.com/api/chat.postMessage', {
        'token': SLACK_TOKEN,
        'channel': SLACK_CHANNEL,
        'text': text,
        'icon_emoji': SLACK_EMOJI,
        'username': SLACK_EMOJI,
        'blocks': json.dumps(blocks) if blocks else None
        }).json()
    except Exception as e:
        print('Exception error when posting to Slack: '+str(e))

    return post_request_results
