from pathlib import Path
import hashlib,importlib.util,json,sqlite3,tempfile,unittest
p=Path(__file__).with_name('parent-session-counts-readonly.py');sp=importlib.util.spec_from_file_location('counts',p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
class Counts(unittest.TestCase):
 def setUp(self):
  self.pub=sqlite3.connect(':memory:');self.ses=sqlite3.connect(':memory:')
  for c in (self.pub,self.ses):c.row_factory=sqlite3.Row
  self.pub.executescript('CREATE TABLE identity_public_accounts(account_id TEXT,person_id TEXT,status TEXT,email_verified_at INTEGER,workspace_id TEXT,email_hash TEXT,password_hash TEXT);CREATE TABLE identity_public_refresh_credentials(account_id TEXT,workspace_id TEXT,status TEXT,expires_at INTEGER,revoked_at INTEGER,refresh_id_hash TEXT,session_id_hash TEXT);')
  self.ses.executescript('CREATE TABLE identity_session_credentials(actor_id TEXT,workspace_id TEXT,status TEXT,expires_at INTEGER,revoked_at INTEGER,session_id_hash TEXT,session_id_hint TEXT,metadata_json TEXT);CREATE TABLE private_family_records(document TEXT);')
  h=hashlib.sha256(m.EMAIL.encode()).hexdigest();self.pub.execute('INSERT INTO identity_public_accounts VALUES(?,?,?,?,?,?,?)',('test_account','test_person','active',20,m.WORKSPACE,h,'FORBIDDEN'))
  for actor,ws,status,exp,rev in [('test_person',m.WORKSPACE,'active',500,0),('test_person',m.WORKSPACE,'revoked',500,50),('test_person',m.WORKSPACE,'active',90,0),('test_person',m.WORKSPACE,'rotated',500,0),('other',m.WORKSPACE,'active',500,0),('test_person','other_workspace','active',500,0)]:self.ses.execute('INSERT INTO identity_session_credentials VALUES(?,?,?,?,?,?,?,?)',(actor,ws,status,exp,rev,'FORBIDDEN','FORBIDDEN','FORBIDDEN'))
  for account,ws,status,exp,rev in [('test_account',m.WORKSPACE,'active',500,0),('test_account',m.WORKSPACE,'revoked',500,50),('other',m.WORKSPACE,'active',500,0)]:self.pub.execute('INSERT INTO identity_public_refresh_credentials VALUES(?,?,?,?,?,?,?)',(account,ws,status,exp,rev,'FORBIDDEN','FORBIDDEN'))
  for c in (self.pub,self.ses):c.set_authorizer(m.authorizer)
 def tearDown(self):self.pub.close();self.ses.close()
 def test_exact_parent_only_counts(self):
  r=m.scan(self.pub,self.ses,100);self.assertEqual(r['canonical_sessions'],{'total':4,'active_unexpired':1,'revoked':1,'revoked_with_timestamp':1,'expired':1,'rotated':1,'other_status':0});self.assertEqual(r['refresh_credentials']['total'],2)
 def test_no_ids_or_forbidden_data_in_output(self):
  text=json.dumps(m.scan(self.pub,self.ses,100));self.assertNotIn('test_person',text);self.assertNotIn('test_account',text);self.assertNotIn('FORBIDDEN',text)
 def test_password_column_forbidden(self):
  with self.assertRaises(sqlite3.DatabaseError):self.pub.execute('SELECT password_hash FROM identity_public_accounts').fetchall()
 def test_session_secrets_and_metadata_forbidden(self):
  for col in ['session_id_hash','session_id_hint','metadata_json']:
   with self.assertRaises(sqlite3.DatabaseError):self.ses.execute('SELECT '+col+' FROM identity_session_credentials').fetchall()
 def test_refresh_hashes_forbidden(self):
  with self.assertRaises(sqlite3.DatabaseError):self.pub.execute('SELECT refresh_id_hash FROM identity_public_refresh_credentials').fetchall()
 def test_customer_table_forbidden(self):
  with self.assertRaises(sqlite3.DatabaseError):self.ses.execute('SELECT document FROM private_family_records').fetchall()
 def test_updates_forbidden(self):
  with self.assertRaises(sqlite3.DatabaseError):self.ses.execute("UPDATE identity_session_credentials SET status='revoked'")
 def test_missing_fixed_account_stops(self):
  self.pub.set_authorizer(None);self.pub.execute('DELETE FROM identity_public_accounts');self.pub.set_authorizer(m.authorizer)
  with self.assertRaisesRegex(ValueError,'exact_synthetic'):m.scan(self.pub,self.ses,100)
 def test_unverified_fixed_account_stops(self):
  self.pub.set_authorizer(None);self.pub.execute('UPDATE identity_public_accounts SET email_verified_at=0');self.pub.set_authorizer(m.authorizer)
  with self.assertRaisesRegex(ValueError,'not_verified'):m.scan(self.pub,self.ses,100)
if __name__=='__main__':unittest.main()
