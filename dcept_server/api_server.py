from flask import Flask, request
from flask_restful import Api, Resource, reqparse
import logging


class APIServer:
    def __init__(self, config, gen_server, cracker):
        self.app = Flask(__name__)
        self.api = Api(self.app)
        self.api.add_resource(GetHoney, config.honeytoken_uri,
                              resource_class_kwargs={'config': config, 'gen_server': gen_server})
        self.api.add_resource(PostCrack, '/notify',
                              resource_class_kwargs={'config': config, 'cracker': cracker})
        self.config = config
        self.gen_server = gen_server
        self.cracker = cracker


    def run(self):
        logging.info(f'API server starting on '
                     f'{self.config.honeytoken_host}:{self.config.honeytoken_port}{self.config.honeytoken_uri} '
                     f'listening for param: {self.config.honeytoken_param_name}')
        self.app.run(host=self.config.honeytoken_host, port=self.config.honeytoken_port)
        # self.app.run(debug=True, host=self.config.honeytoken_host, port=self.config.honeytoken_port)


class GetHoney(Resource):
    def __init__(self, **kwargs):
        self.config = kwargs['config']
        self.gen_server = kwargs['gen_server']

    def get(self):
        machine = request.args.get(self.config.honeytoken_param_name)
        if not machine:
            logging.debug(f'Bad request from IP: {request.remote_addr}: {request.url}')
            return '', 204
        logging.info(f'Request from IP: {request.remote_addr} workstation: {machine}')

        password = self.gen_server.gen_pass(machine)

        response = {'d': self.config.domain, 'u': self.config.honey_username, 'p': password}
        logging.info(f'Response generated: {response}')
        return response


# arguments validation
postcrack_args = reqparse.RequestParser()
postcrack_args.add_argument('kerb_name', type=str, required=True, location='form')
postcrack_args.add_argument('kerb_realm', type=str, required=True, location='form')
postcrack_args.add_argument('kerb_etype', type=str, required=True, location='form')
postcrack_args.add_argument('enc_timestamp', type=str, required=True, location='form')


class PostCrack(Resource):
    def __init__(self, **kwargs):
        self.config = kwargs['config']
        self.cracker = kwargs['cracker']

    def post(self):
        args = postcrack_args.parse_args()
        logging.info(f"Remote crack request recived from {request.remote_addr}: {args}")

        self.cracker.enqueue_job(args['kerb_name'], args['kerb_realm'], args['kerb_etype'], args['enc_timestamp'])

        return '', 200
