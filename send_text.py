import os
from twilio.rest import Client
from decouple import config


twilio_phone_number = config('TWILIO_PHONE_NUMBER')

def send_text_msg(destination: str, msg: str):
    account_sid = config('TWILIO_ACCOUNT_SID')
    auth_token = config('TWILIO_AUTH_TOKEN')
    client = Client(account_sid, auth_token)

    message = client.messages \
                    .create(
                        body=msg,
                        from_=twilio_phone_number,
                        to=destination
                    )


# test
if __name__ == '__main__':
    send_text_msg('your_text_account_number_here', 'Hello from Python!')
