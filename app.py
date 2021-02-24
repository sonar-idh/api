import binascii
import hashlib
import os
import ast
import re
import sys
import uuid
import json
from dotenv import load_dotenv, find_dotenv
from datetime import datetime
from functools import wraps

from flask import Flask, g, request, send_from_directory, abort, request_started, jsonify, send_file
from flask_cors import CORS
from flask_restful import Resource, reqparse
from flask_restful_swagger_2 import Api, swagger, Schema
from flask_json import FlaskJSON, json_response

from neo4j import GraphDatabase, basic_auth
from neo4j.exceptions import Neo4jError
import neo4j.time
import logging

UPLOAD_DIRECTORY = "C:/Users/elle01/.Neo4jDesktop/neo4jDatabases/database-180b22fd-7fb0-471f-a73e-cdba256702c1/installation-3.5.8/import/"

#if not os.path.exists(UPLOAD_DIRECTORY):
#    os.makedirs(UPLOAD_DIRECTORY)


load_dotenv(find_dotenv())

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

CORS(app)
FlaskJSON(app)

api = Api(app, title='SoNAR API Demo', api_version='0.0.10')


@api.representation('application/json')
def output_json(data, code, headers=None):
    return json_response(data_=data, headers_=headers, status_=code)


def env(key, default=None, required=True):
    """
    Retrieves environment variables and returns Python natives. The (optional)
    default will be returned if the environment variable does not exist.
    """
    try:
        value = os.environ[key]
        return ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value
    except KeyError:
        if default or not required:
            return default
        raise RuntimeError("Missing required environment variable '%s'" % key)


DATABASE_USERNAME = env('SONAR_DATABASE_USERNAME')
DATABASE_PASSWORD = env('SONAR_DATABASE_PASSWORD')
DATABASE_URL = env('SONAR_DATABASE_URL')

driver = GraphDatabase.driver(DATABASE_URL, auth=basic_auth(DATABASE_USERNAME, str(DATABASE_PASSWORD)))

app.config['SECRET_KEY'] = env('SECRET_KEY')


def get_db():
    if not hasattr(g, 'neo4j_db'):
        g.neo4j_db = driver.session()
    return g.neo4j_db


@app.teardown_appcontext
def close_db(error):
    if hasattr(g, 'neo4j_db'):
        g.neo4j_db.close()


## 
def set_user(sender, **extra):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        g.user = {'id': None}
        return
    match = re.match(r'^Token (\S+)', auth_header)
    if not match:
        abort(401, 'invalid authorization format. Follow `Token <token>`')
        return
    token = match.group(1)

    def get_user_by_token(tx, token):
        return tx.run(
            '''
            MATCH (user:User {api_key: $api_key}) RETURN user
            ''', {'api_key': token}
        ).single()

    db = get_db()
    result = db.read_transaction(get_user_by_token, token)
    try:
        g.user = result['user']
    except (KeyError, TypeError):
        abort(401, 'invalid authorization key')
    return
request_started.connect(set_user, app)


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return {'message': 'no authorization provided'}, 401
        return f(*args, **kwargs)
    return wrapped


## Models for entity types
class EntityModel(Schema):
    type = 'object'
    properties = {
        'Id': {
            'type': 'string',
        },
        'Name': {
            'type': 'string',
        },
        'VariantName': {
            'type': 'string',
        },
        'OldId': {
            'type': 'string',
        },
        'Uri': {
            'type': 'string',
        },
        'GenType': {
            'type': 'string',
        },
        'SpecType': {
            'type': 'string',
        },
        'Gender': {
            'type': 'string',
        },
        'DateApproxOriginal': {
            'type': 'string',
        },
        'DateApproxBegin': {
            'type': 'string',
        },
        'DateApproxEnd': {
            'type': 'string',
        },
        'DateStrictOriginal': {
            'type': 'string',
        },
        'DateStrictBegin': {
            'type': 'string',
        },
        'DateStrictEnd': {
            'type': 'string',
        },
        'DateOriginal': {
            'type': 'string',
        },
        'SubUnit': {
            'type': 'string',
        },
        'Info': {
            'type': 'string',
        },
        'Place': {
            'type': 'string',
        },
        'Creator': {
            'type': 'string',
        },
        'Medium': {
            'type': 'string',
        },
        'Lang': {
            'type': 'string',
        },
        'GenSubdiv': {
            'type': 'string',
        },
        'GeoArea': {
            'type': 'string',
        },
        'Coordinates': {
            'type': 'string',
        },
        'IdGeonames': {
            'type': 'string',
        }
    }

class EntityRelationModel(Schema):
    type = 'object'
    properties = {
        'Id': {
            'type': 'string',
        },
        'Name': {
            'type': 'string',
        },
        'VariantName': {
            'type': 'string',
        },
        'OldId': {
            'type': 'string',
        },
        'Uri': {
            'type': 'string',
        },
        'GenType': {
            'type': 'string',
        },
        'SpecType': {
            'type': 'string',
        },
        'Gender': {
            'type': 'string',
        },
        'DateApproxOriginal': {
            'type': 'string',
        },
        'DateApproxBegin': {
            'type': 'string',
        },
        'DateApproxEnd': {
            'type': 'string',
        },
        'DateStrictOriginal': {
            'type': 'string',
        },
        'DateStrictBegin': {
            'type': 'string',
        },
        'DateStrictEnd': {
            'type': 'string',
        },
        'DateOriginal': {
            'type': 'string',
        },
        'SubUnit': {
            'type': 'string',
        },
        'Info': {
            'type': 'string',
        },
        'Place': {
            'type': 'string',
        },
        'Creator': {
            'type': 'string',
        },
        'Medium': {
            'type': 'string',
        },
        'Lang': {
            'type': 'string',
        },
        'GenSubdiv': {
            'type': 'string',
        },
        'GeoArea': {
            'type': 'string',
        },
        'Coordinates': {
            'type': 'string',
        },
        'IdGeonames': {
            'type': 'string',
        },
        'Genre': {
            'type': 'string',
        },
        'SourcePath': {
            'type': 'string',
        },
        'Source': {
            'type': 'string',
        },
        'SourceType': {
            'type': 'string',
        },
        'TypeAddInfo': {
            'type': 'string',
        },
        'TempValidity': {
            'type': 'string',
        }
    }

class StatisticModel(Schema):
    type = 'object'
    properties = {
        'labelCount': {
            'type': 'string',
        },
        'labels': {
            'type': 'string',
        },
        'nodeCount': {
            'type': 'string',
        },
        'propertyKeyCount': {
            'type': 'string',
        },
        'relCount': {
            'type': 'string',
        },
        'relTypeCount': {
            'type': 'string',
        },
        'relTypes': {
            'type': 'string',
        },
        'status': {
            'type': 'string',
        }
    }


class UserModel(Schema):
    type = 'object'
    properties = {
        'id': {
            'type': 'string',
        },
        'username': {
            'type': 'string',
        },
        'avatar': {
            'type': 'object',
        }
    }


## Serialize Infos from node or edge
def serialize_entity(entity, label = None):
    complete_entity = {}
    for key_name in ["Id", "OldId", "Uri", "GenType", "SpecType", "Name", "VariantName", "Gender", "DateOriginal", "DateApproxOriginal", "DateApproxBegin", "DateApproxEnd", "DateStrictOriginal", "DateStrictBegin", "DateStrictEnd", "SubUnit", "Info", "Place", "Date", "Creator", "Medium", "Lang", "GenSubdiv", "GeoArea", "Coordinates", "IdGeonames", "Genre"]:
        if key_name in entity: complete_entity[key_name] = entity[key_name]
    if label != None: complete_entity["label"] = label
    return complete_entity

def serialize_relation(relation, label = None):
    complete_relation = {}
    for key_name in ["SourceType", "TypeAddInfo", "TempValidity", "Source"]:
        if key_name in relation: complete_relation[key_name] = relation[key_name]
    if label != None: complete_relation["label"] = label
    return complete_relation

def serialize_user(user):
    return {
        'id': user['id'],
        'username': user['username'],
        'avatar': {
            'full_size': 'https://www.gravatar.com/avatar/{}?d=retro'.format(hash_avatar(user['username']))
        }
    }


def hash_password(username, password):
    if sys.version[0] == 2:
        s = '{}:{}'.format(username, password)
    else:
        s = '{}:{}'.format(username, password).encode('utf-8')
    return hashlib.sha256(s).hexdigest()


def hash_avatar(username):
    if sys.version[0] == 2:
        s = username
    else:
        s = username.encode('utf-8')
    return hashlib.md5(s).hexdigest()


class ApiDocs(Resource):
    def get(self, path=None):
        if not path:
            path = 'index.html'
        return send_from_directory('swaggerui', path)

class Statistics(Resource):
    @swagger.doc({
        'tags': ['stats'],
        'summary': 'Return statistics of a graph database',
        'description': 'Returns informations of labels, nodes, edges',
        'parameters': [],
        'responses': {
            '200': {
                'description': 'Statistics',
                'schema': StatisticModel,
            },
            '404': {
                'description': 'statistic not found'
            },
        }
    })
    def get(self):
        def get_stats(tx):
            return list(tx.run(
                '''
                CALL apoc.meta.stats()
                '''))
        db = get_db()
        results = db.read_transaction(get_stats)
        return results[0][8]

## ENTITY

class EntityId(Resource):
    @swagger.doc({
        'tags': ['entity'],
        'summary': 'Find a entity by id',
        'description': 'Returns a entity and it properties',
        'parameters': [
            {
                'name': 'id',
                'description': 'id of node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Properties of a entity',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'entity not found'
            },
        }
    })
    def get(self, id):
        def get_entity_by_id(tx, i):
            return list(tx.run(
                '''
                MATCH (p) WHERE p.Id=$i RETURN p, labels(p)[0] as l
                ''', {'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_entity_by_id, id)
        return [serialize_entity(record['p'], record['l']) for record in results]

class EntityLabelId(Resource):
    @swagger.doc({
        'tags': ['entity'],
        'summary': 'Find a entity by label and id',
        'description': 'Returns a entity and it properties',
        'parameters': [
            {
                'name': 'label',
                'description': 'label for node (PerName, CorpName, GeoName etc.)',
                'in': 'path',
                'type': 'sting',
                'required': True
            },
            {
                'name': 'id',
                'description': 'id of node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Properties of a entity',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'entity not found'
            },
        }
    })
    def get(self, label, id):
        def get_entity_by_labelId(tx, lb, i):
            return list(tx.run(
                '''
                MATCH (p) WHERE labels(p)[0]=$lb and p.Id=$i RETURN p, labels(p)[0] as l
                ''', {'lb': lb, 'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_entity_by_labelId, label, id)
        return [serialize_entity(record['p'], record['l']) for record in results]

class EntityLabel(Resource):
    @swagger.doc({
        'tags': ['entity'],
        'summary': 'Find a entities by label',
        'description': 'Returns entities (limit 300 nodes) and it properties',
        'parameters': [
            {
                'name': 'label',
                'description': 'label for node (PerName, CorpName, GeoName etc.)',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Properties of a entity',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'entity not found'
            },
        }
    })
    def get(self, label):
        def get_entity_list(tx, lb):
            return list(tx.run(
                '''
                MATCH (p) WHERE labels(p)[0]=$lb RETURN p, labels(p)[0] as l LIMIT 300
                ''', {'lb': lb}
            ))
        db = get_db()
        results = db.read_transaction(get_entity_list, label)
        return [serialize_entity(record['p'],record['l']) for record in results]


## SEARCH

class SearchEntity(Resource):
    @swagger.doc({
        'tags': ['search'],
        'summary': 'Search a entity by name',
        'description': 'Returns a list of entities (limit 300) and it properties',
        'parameters': [
            {
                'name': 'name',
                'description': 'name of node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Properties of a entity',
                'schema': EntityModel,
            },
            '404': {
                'description': 'entity not found'
            },
        }
    })
    def get(self, name):
        def get_entity_by_name(tx, n):
            return list(tx.run(
                '''
                MATCH (p) WHERE p.Name CONTAINS $n OR p.VariantName CONTAINS $n RETURN p, labels(p)[0] as l LIMIT 300
                ''', {'n': n}
            ))
        db = get_db()
        results = db.read_transaction(get_entity_by_name, name)
        return [serialize_entity(record['p'],record['l']) for record in results]

class SearchRelation(Resource):
    @swagger.doc({
        'tags': ['search'],
        'summary': 'Search a relation by name of source and target nodes',
        'description': 'Returns a list of relations (limit 300), entities and it properties',
        'parameters': [
            {
                'name': 'source',
                'description': 'name of source node',
                'in': 'path',
                'type': 'sting',
                'required': True
            },
            {
                'name': 'target',
                'description': 'name of target node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, source, target):
        def get_relation_by_name(tx, s, t):
            return list(tx.run(
                '''
                MATCH (p1)-[r]->(p2) WHERE (p1.Name CONTAINS $s OR p1.VariantName CONTAINS $s) AND (p2.Name CONTAINS $t OR p2.VariantName CONTAINS $t) RETURN p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'s': s, 't': t}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_name, source, target)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]

## RELATION
class RelationId(Resource):
    @swagger.doc({
        'tags': ['relation'],
        'summary': 'Find relations by id of source or target',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'id',
                'description': 'id of source node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, id):
        def get_relation_by_id(tx, i):
            return list(tx.run(
                '''
                MATCH (p1)-[r]->(p2) WHERE (p1.Id=$i OR p2.Id=$i) RETURN p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_id, id)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]

class RelationSourceTarget(Resource):
    @swagger.doc({
        'tags': ['relation'],
        'summary': 'Find a relations by source and target ids',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'source_id',
                'description': 'id of source node',
                'in': 'path',
                'type': 'sting',
                'required': True
            },
            {
                'name': 'target_id',
                'description': 'id of target node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, source, target):
        def get_relation_by_id(tx, s, t):
            return list(tx.run(
                '''
                MATCH (p1)-[r]->(p2) WHERE p1.Id=$s AND p2.Id=$t RETURN p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'s': s, 't': t}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_id, source, target)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]

class RelationLabel(Resource):
    @swagger.doc({
        'tags': ['relation'],
        'summary': 'Find relations by label',
        'description': 'Returns relations, source and target entities and it properties  (limit 300)',
        'parameters': [
            {
                'name': 'label',
                'description': 'label for node (RelationToPerName, RelationToCorpName, RelationToGeoName etc.)',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, label):
        def get_relation_list(tx, lb):
            return list(tx.run(
                '''
                MATCH (p1)-[r]-(p2) WHERE TYPE(r)=$lb RETURN p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'lb': lb}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_list, label)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]

class RelationLabelId(Resource):
    @swagger.doc({
        'tags': ['relation'],
        'summary': 'Find relations by label and id of source or target',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'label',
                'description': 'label for node (RelationToPerName, RelationToCorpName, RelationToGeoName etc.)',
                'in': 'path',
                'type': 'sting',
                'required': True
            },
            {
                'name': 'id',
                'description': 'id of source node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, label, id):
        def get_relation_by_labelId(tx, lb, i):
            return list(tx.run(
                '''
                MATCH (p1)-[r]->(p2) WHERE TYPE(r)=$lb AND (p1.Id=$i OR p2.Id=$i) RETURN p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'lb': lb, 'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_labelId, label, id)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]

class RelationLabelSourceTarget(Resource):
    @swagger.doc({
        'tags': ['relation'],
        'summary': 'Find a relations by label, source and target ids',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'label',
                'description': 'label for node (RelationToPerName, RelationToCorpName, RelationToGeoName etc.)',
                'in': 'path',
                'type': 'sting',
                'required': True
            },
            {
                'name': 'source_id',
                'description': 'id of source node',
                'in': 'path',
                'type': 'sting',
                'required': True
            },
            {
                'name': 'target_id',
                'description': 'id of target node',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, label, source, target):
        def get_relation_by_labelSourceTarget(tx, lb, s, t):
            return list(tx.run(
                '''
                MATCH (p1)-[r]->(p2) WHERE TYPE(r)=$lb AND p1.Id=$s AND p2.Id=$t RETURN p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'lb': lb, 's': s, 't': t}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_labelSourceTarget, label, source, target)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]


## NETWORKS

#cypherStatement #2
class FirstDegreeRelation(Resource):
    @swagger.doc({
        'tags': ['network'],
        'summary': 'Find network of first degree by id of a person',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'id',
                'description': 'id of source node (person)',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, id):
        def get_relation_by_id(tx, i):
            return list(tx.run(
                '''
                MATCH (p1:PerName) - [r:RelationToTopicTerm | RelationToGeoName | RelationToCorpName | RelationToMeetName | RelationToUniTitle | SocialRelation | RelationToResource | RelationToPerName] - (p2)
                WHERE p1.Id = $i
                RETURN DISTINCT p1, p2, labels(p1)[0] as l1, labels(p2)[0] as l2, r, TYPE(r) as lr LIMIT 300
                ''', {'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_id, id)
        return [{'source': serialize_entity(record['p1'], record['l1']), 'target': serialize_entity(record['p2'], record['l2']), 'relation': serialize_relation(record['r'], record['lr'])} for record in results]

#cypherStatement #1
class FriendsOfFriends(Resource):
    @swagger.doc({
        'tags': ['network'],
        'summary': 'Find network of friends by id of a person',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'id',
                'description': 'id of source node (person)',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, id):
        def get_relation_by_id(tx, i):
            return list(tx.run(
                '''
                MATCH (p1:PerName) - [r1:RelationToPerName | RelationToCorpName | SocialRelation] - (p2) - [r2:RelationToTopicTerm | RelationToGeoName | RelationToMeetName | RelationToUniTitle | RelationToCorpName ] - (p3)
                WHERE (p1.Id = $i AND p2:PerName)
                RETURN DISTINCT p1, p2, p3, labels(p1)[0] as l1, labels(p2)[0] as l2, labels(p3)[0] as l3, r1, TYPE(r1) as lr1, r2, TYPE(r2) as lr2 LIMIT 300
                ''', {'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_id, id)
        return [{'source': serialize_entity(record['p1'], record['l1']), 
                'target1': serialize_entity(record['p2'], record['l2']), 
                'target2': serialize_entity(record['p3'], record['l3']), 
                'relation1': serialize_relation(record['r1'], record['lr1']),
                'relation2': serialize_relation(record['r2'], record['lr2'])} for record in results]

#cypherStatement #3
class FriendsAndResources(Resource):
    @swagger.doc({
        'tags': ['network'],
        'summary': 'Find network of friends and resources by id of a person',
        'description': 'Returns relations, source and target entities and it properties (limit 300)',
        'parameters': [
            {
                'name': 'id',
                'description': 'id of source node (person)',
                'in': 'path',
                'type': 'sting',
                'required': True
            }
        ],
        'responses': {
            '200': {
                'description': 'Relation, entities and properties',
                'schema': EntityRelationModel,
            },
            '404': {
                'description': 'relation not found'
            },
        }
    })
    def get(self, id):
        def get_relation_by_id(tx, i):
            return list(tx.run(
                '''
                MATCH (p1:PerName) - [r1:RelationToResource | RelationToPerName] - (p2)
                - [r2:RelationToPerName | RelationToResource] - (p3)
                WHERE p1.Id = $i
                RETURN DISTINCT p1, p2, p3, labels(p1)[0] as l1, labels(p2)[0] as l2, labels(p3)[0] as l3, r1, TYPE(r1) as lr1, r2, TYPE(r2) as lr2 LIMIT 300
                ''', {'i': i}
            ))
        db = get_db()
        results = db.read_transaction(get_relation_by_id, id)
        return [{'source': serialize_entity(record['p1'], record['l1']), 
                'target1': serialize_entity(record['p2'], record['l2']), 
                'target2': serialize_entity(record['p3'], record['l3']), 
                'relation1': serialize_relation(record['r1'], record['lr1']),
                'relation2': serialize_relation(record['r2'], record['lr2'])} for record in results]


class Export(Resource):
    @swagger.doc({
        'tags': ['export'],
        'summary': 'Export a data via API',
        'description': 'Export a data via API',
        'parameters': [
            {
                'name': 'path',
                'description': 'path of source',
                'in': 'path',
                'type': 'path',
                'required': True
            }
        ],
        'responses': {
            '201': {
                'description': 'export data',
                'schema': EntityRelationModel,
            },
            '400': {
                'description': 'Error message(s)',
            },
        }
    })
    def post(self, path):
        def get_relation_by_id(tx, i):
            q = "MATCH (p1)-[r]->(p2) WHERE (p1.Id='(DE-588)120038234') RETURN p1 as source, p2 as target, r as relation LIMIT 5"
            return tx.run(
                '''
                WITH $q AS query
                CALL apoc.export.json.query(query, "output.json", {format: "plain"})
                YIELD file
                RETURN file
                ''', {'q': q}
            )
        db = get_db()
        results = db.read_transaction(get_relation_by_id, path)
        """Download a file."""
        return send_file("C:/Users/elle01/.Neo4jDesktop/neo4jDatabases/database-180b22fd-7fb0-471f-a73e-cdba256702c1/installation-3.5.8/import/output.json", as_attachment=True)

class Export2(Resource):
    @swagger.doc({
        'tags': ['export'],
        'summary': 'Export a data via API',
        'description': 'Export a data via API',
        'parameters': [],
        'responses': {
            '201': {
                'description': 'export data',
                'schema': EntityRelationModel,
            },
            '400': {
                'description': 'Error message(s)',
            },
        }
    })
    def get(self):
        """Endpoint to list files on the server."""
        files = []
        for filename in os.listdir(UPLOAD_DIRECTORY):
            path = os.path.join(UPLOAD_DIRECTORY, filename)
            if os.path.isfile(path):
                files.append(filename)
        return jsonify(files)


class Register(Resource):
    @swagger.doc({
        'tags': ['users'],
        'summary': 'Register a new user',
        'description': 'Register a new user',
        'parameters': [
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {
                            'type': 'string',
                        },
                        'password': {
                            'type': 'string',
                        }
                    }
                }
            },
        ],
        'responses': {
            '201': {
                'description': 'Your new user',
                'schema': UserModel,
            },
            '400': {
                'description': 'Error message(s)',
            },
        }
    })
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username:
            return {'username': 'This field is required.'}, 400
        if not password:
            return {'password': 'This field is required.'}, 400

        def get_user_by_username(tx, username):
            return tx.run(
                '''
                MATCH (user:User {username: $username}) RETURN user
                ''', {'username': username}
            ).single()

        db = get_db()
        result = db.read_transaction(get_user_by_username, username)
        if result and result.get('user'):
            return {'username': 'username already in use'}, 400

        def create_user(tx, username, password):
            return tx.run(
                '''
                CREATE (user:User {id: $id, username: $username, password: $password, api_key: $api_key}) RETURN user
                ''',
                {
                    'id': str(uuid.uuid4()),
                    'username': username,
                    'password': hash_password(username, password),
                    'api_key': binascii.hexlify(os.urandom(20)).decode()
                }
            ).single()

        results = db.write_transaction(create_user, username, password)
        user = results['user']
        return serialize_user(user), 201

class Login(Resource):
    @swagger.doc({
        'tags': ['users'],
        'summary': 'Login',
        'description': 'Login',
        'parameters': [
            {
                'name': 'body',
                'in': 'body',
                'schema': {
                    'type': 'object',
                    'properties': {
                        'username': {
                            'type': 'string',
                        },
                        'password': {
                            'type': 'string',
                        }
                    }
                }
            },
        ],
        'responses': {
            '200': {
                'description': 'succesful login'
            },
            '400': {
                'description': 'invalid credentials'
            }
        }
    })
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        if not username:
            return {'username': 'This field is required.'}, 400
        if not password:
            return {'password': 'This field is required.'}, 400

        def get_user_by_username(tx, username):
            return tx.run(
                '''
                MATCH (user:User {username: $username}) RETURN user
                ''', {'username': username}
            ).single()

        db = get_db()
        result = db.read_transaction(get_user_by_username, username)
        try:
            user = result['user']
        except KeyError:
            return {'username': 'username does not exist'}, 400

        expected_password = hash_password(user['username'], password)
        if user['password'] != expected_password:
            return {'password': 'wrong password'}, 400
        return {
            'token': user['api_key']
        }

class UserMe(Resource):
    @swagger.doc({
        'tags': ['users'],
        'summary': 'Get your user',
        'description': 'Get your user',
        'parameters': [{
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'default': 'Token <token goes here>',
        }],
        'responses': {
            '200': {
                'description': 'the user',
                'schema': UserModel,
            },
            '401': {
                'description': 'invalid / missing authentication',
            },
        }
    })
    @login_required
    def get(self):
        return serialize_user(g.user)



api.add_resource(ApiDocs, '/docs', '/docs/<path:path>')
#api.add_resource(Register, '/api/v0/register')
#api.add_resource(Login, '/api/v0/login')
#api.add_resource(UserMe, '/api/v0/users/me')

## Entitäten zurückgeben
api.add_resource(EntityId, '/api/v0/entity/<string:id>.json')
api.add_resource(EntityLabel, '/api/v0/entity/list/<string:label>.json')
api.add_resource(EntityLabelId, '/api/v0/entity/<string:label>/<string:id>.json')

## Relationen zurückgeben
api.add_resource(RelationId, '/api/v0/relation/<string:id>.json')
api.add_resource(RelationSourceTarget, '/api/v0/relation/<string:source>:<string:target>.json')
api.add_resource(RelationLabel, '/api/v0/relation/list/<string:label>.json')
api.add_resource(RelationLabelId, '/api/v0/relation/<string:label>/<string:id>.json')
api.add_resource(RelationLabelSourceTarget, '/api/v0/relation/<string:label>/<string:source>:<string:target>.json')

## Entitäten/Relationen suchen (nach Namen)
api.add_resource(SearchEntity, '/api/v0/search/<string:name>.json')
api.add_resource(SearchRelation, '/api/v0/search/<string:source>:<string:target>.json')

## Netzwerke zurückgeben
api.add_resource(FirstDegreeRelation, '/api/v0/network/all/<string:id>.json')
api.add_resource(FriendsOfFriends, '/api/v0/network/friends/<string:id>.json')
api.add_resource(FriendsAndResources, '/api/v0/network/resources/<string:id>.json')

## Export
#api.add_resource(Export, '/api/v0/export/sonar')
api.add_resource(Export, '/api/v0/export/<path:path>')
#api.add_resource(Export, '/api/v0/export')

api.add_resource(Statistics, '/api/v0/stats.json')

