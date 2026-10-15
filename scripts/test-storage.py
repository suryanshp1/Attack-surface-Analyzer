"""Verify a disposable database and bucket; never writes fixture data to the live workspace."""
import os,subprocess,urllib.parse
values={}
for line in open('.env'):
    if '=' in line and not line.startswith('#'):
        key,value=line.strip().split('=',1);values[key]=value
app='postgres://surfacer_app:'+urllib.parse.quote(values['POSTGRES_APP_PASSWORD'],safe='')+'@db:5432/surfacer_test'
admin='postgres://surfacer:'+urllib.parse.quote(values['POSTGRES_PASSWORD'],safe='')+'@db:5432/surfacer_test'
def run(args):subprocess.run(args,check=True)
run(['docker','compose','exec','-T','db','psql','-U','surfacer','-d','surfacer','-v','ON_ERROR_STOP=1','-c','CREATE DATABASE surfacer_test;'])
try:
    run(['docker','compose','run','--rm','-e','DATABASE_URL='+admin,'migrate'])
    run(['docker','run','--rm','--network','attack-surface_control','--env-file','.env','-e','TEST_DATABASE_URL='+app,'-e','S3_ENDPOINT=minio:9000','--entrypoint','/native-tests','surfacer-native-test','-test.v','-test.run=TestStorageIntegration'])
finally:
    run(['docker','compose','exec','-T','db','psql','-U','surfacer','-d','surfacer','-v','ON_ERROR_STOP=1','-c','DROP DATABASE surfacer_test WITH (FORCE);'])
