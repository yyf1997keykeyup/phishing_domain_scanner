import certstream

certstream_calidog_url = 'wss://certstream.calidog.io'


def listen_func(message, context):
    pass
    # todo


if __name__ == '__main__':
    certstream.listen_for_events(listen_func, url=certstream_calidog_url)
