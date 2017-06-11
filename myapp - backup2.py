from google.appengine.api import urlfetch

import os
import webapp2
import json
import logging
import string
import random
import httplib
import hashlib
import httplib2
import urllib
import ndb_json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import verify_id_token
from google.appengine.ext import ndb

CLIENT_ID="675455219176-vcn6gvnm6lnpmb2s3a0ei1cqbm6g55ma.apps.googleusercontent.com"
CLIENT_SECRET = "BUNnDjqjli8glihvapMvnAvy"
REDIRECT_URI = "https://oauth2-166722.appspot.com/oauth"
TOKEN_URL = "https://www.googleapis.com/oauth2/v4/token"

NONADMIN_TOKEN = "1/vSkt8DswcdekDii6ZOueusLuGyKUxabYfazYvMRt_kg"
ADMIN_TOKEN = "1/zCnPfy_kE2PoDmMBkrs3ll1gnWXII-e_05Sdhhc8Q9A" # Admin, 112755314084608193841

AUD = "675455219176-vcn6gvnm6lnpmb2s3a0ei1cqbm6g55ma.apps.googleusercontent.com"

WEATHER_API_KEY = "67ef4274fb880294e67af728d18e2b4f"


class User(ndb.Model):
	gid = ndb.StringProperty(required=True)
	age = ndb.IntegerProperty(required=True)
	hairColor = ndb.StringProperty(required=True)
	isAdmin = ndb.BooleanProperty()
	
	
class House(ndb.Model):
	trackedBy = ndb.StringProperty(required=True)
	address = ndb.StringProperty(required=True)
	price = ndb.StringProperty(required=True)
	zip = ndb.StringProperty(required=True)
	

class HouseHandler(webapp2.RequestHandler):
	def get(self):
		try:
			# If a valid token was passed then show user's houses
			userToken = self.request.headers['Authorization']
			googleId = getGoogleId(userToken)
			
			logging.warning(googleId)
			if (googleId):
				houses = getUserHouses(googleId)
				self.response.write(houses)
				self.response.headers['Content-Type'] = 'application/json'
			
			else:
				self.response.write("Invalid token")
				self.response.status = 400
		
		except:
			# Show all houses
			houses = getAllHouses()
			output = json.dumps(houses)
			self.response.write(output)
			self.response.headers['Content-Type'] = 'application/json'
	
	def post(self):
		try:
			userToken = self.request.headers['Authorization']
			googleId = getGoogleId(userToken)
			
			# If googleId is nothing, then the authorization token was invalid
			if (not googleId):
				self.response.status = 403
				self.response.write("Invalid authorization header")
				return
			
			user = User.query(User.gid == googleId).get()
			
			if (user):
				house_data = json.loads(self.request.body)
				addressValid = addressAndZipAreValid(house_data)
				
				if (addressValid):
					# Create the house
					if ('address' in house_data and \
						'price' in house_data and \
						'zip' in house_data):
						
						new_house = House(
							address=house_data['address'],
							price=house_data['price'],
							zip=house_data['zip'],
							trackedBy=user.key.urlsafe()
						)
						
						new_house.put()
						house_dict = new_house.to_dict()
						house_dict['id'] = new_house.key.urlsafe()
						self.response.status = 201
						self.response.write(json.dumps(house_dict))
						self.response.headers['Content-Type'] = 'application/json'
						
					else:
						self.response.status = 400
					
				else:
					self.response.status = 400
			
			else:
				self.response.status = 400
		
		except:
			self.response.status = 400

			
class HouseIdHandler(webapp2.RequestHandler):
	def get(self, id=None):
		try:
			key = ndb.Key(urlsafe=id)
			house = House.get_by_id(key.id())
		
		except:
			self.response.status = 404
			return
			
		try:
			dict = house.to_dict()
			dict['id'] = id
			self.response.write(json.dumps(dict))
			self.response.headers['Content-Type'] = 'application/json'
								
		except:
			self.response.status = 400
	
	def patch(self, id=None):
		# Check if the house id exists
		try:
			key = ndb.Key(urlsafe=id)
			house = House.get_by_id(key.id())
		
		except:
			self.response.status = 404
			return
			
		try:
			# Check if this is a valid user
			try:
				userToken = self.request.headers['Authorization']
			except:
				self.response.code = 403
				return
				
			googleId = getGoogleId(userToken)
			
			# If googleId is nothing, then the authorization token was invalid
			if (not googleId):
				self.response.status = 403
				self.response.write("Invalid authorization header")
				return
			
			user = User.query(User.gid == googleId).get()
			if (user):
				userId = user.key.urlsafe()
				house_data = json.loads(self.request.body)
				
				# Check that the replaced house belongs to this user
				key = ndb.Key(urlsafe=id)
				house = House.get_by_id(key.id())
				house_json = ndb_json.dumps(house)
				house_dict = ndb_json.loads(house_json)
				
				if (house_dict['trackedBy'] != userId):
					
					# Edit the house
					if ('price' in house_data):
						
						self.response.status = 204
						
					else:
						self.response.status = 400
						
				else:
					self.response.status = 403
			
			else:
				self.response.status = 400
		
		except:
			self.response.status = 400
	
	def put(self, id=None):
		# Check if the house id exists
		try:
			key = ndb.Key(urlsafe=id)
			house = House.get_by_id(key.id())
		
		except:
			self.response.status = 404
			return
			
		try:
			# Check if this is a valid user
			userToken = self.request.headers['Authorization']
			googleId = getGoogleId(userToken)
			
			# If googleId is nothing, then the authorization token was invalid
			if (not googleId):
				self.response.status = 403
				self.response.write("Invalid authorization header")
				return
			
			user = User.query(User.gid == googleId).get()
			if (user):
				userId = user.key.urlsafe()
				house_data = json.loads(self.request.body)
				
				# Check that the replaced house belongs to this user
				key = ndb.Key(urlsafe=id)
				old_house = House.get_by_id(key.id())
				old_house_json = ndb_json.dumps(old_house)
				old_house_dict = ndb_json.loads(old_house_json)
				
				if (old_house_dict['trackedBy'] != userId):
					
					addressValid = addressAndZipAreValid(house_data)
					
					if (addressValid):
						# Create the house
						if ('address' in house_data and \
							'price' in house_data and \
							'zip' in house_data):
							
							new_house = House(
								address=house_data['address'],
								price=house_data['price'],
								zip=house_data['zip'],
								trackedBy=userId
							)
							
							new_house.put()
							old_house.key.delete()
							
							house_dict = new_house.to_dict()
							house_dict['id'] = new_house.key.urlsafe()
							self.response.status = 201
							self.response.write(json.dumps(house_dict))
							self.response.headers['Content-Type'] = 'application/json'
							
						else:
							self.response.status = 400
						
					else:
						self.response.status = 400
						
				else:
					self.response.status = 403
			
			else:
				self.response.status = 400
		
		except:
			self.response.status = 400
		
	
def addressAndZipAreValid(house_data):
	try:
		queryCount = House.query(ndb.AND(House.zip == house_data['zip'], House.address == house_data['address'])).count()
		if (queryCount > 0):
			return False
		else:
			return True
		
	except:
		return False
		
	
def getUserHouses(googleId):
	houses = House.query(House.trackedBy == googleId).fetch()
	house_json = ndb_json.dumps(houses)
	house_dict = ndb_json.loads(house_json)
	
	for i in range(0, House.query(House.trackedBy == googleId).count()):
		house_dict[i]['id'] = houses[i].key.urlsafe()
	
	return house_json

	
def getAllHouses():
	query = House.query()
	allEntities = query.fetch()
	query_json = ndb_json.dumps(query)
	query_dict = ndb_json.loads(query_json)
	
	for i in range(0, House.query().count()):
		query_dict[i]['id'] = allEntities[i].key.urlsafe()
		
	return query_dict

	
class UserHandler(webapp2.RequestHandler):
	def get(self):
		query = User.query()
		allEntities = query.fetch()
		query_json = ndb_json.dumps(query)
		query_dict = ndb_json.loads(query_json)
		
		for i in range(0, User.query().count()):
			query_dict[i].pop('gid', None) # Remove google ID from public
			query_dict[i]['id'] = allEntities[i].key.urlsafe()
		
		output = json.dumps(query_dict)
		self.response.write(output)
		self.response.headers['Content-Type'] = 'application/json'
			
	def post(self):
		try:
			if (userIsAdmin(self)):
				user_data = json.loads(self.request.body)
				
				# Check if this user already exists
				userExists = User.query(User.gid == user_data['gid']).get()
				if not userExists == None:
					self.response.write('This user already exists')
					self.response.status = 400
					return
				
				# Create the user
				if ('gid' in user_data and \
					'age' in user_data and \
					'hairColor' in user_data and \
					'isAdmin' in user_data):
					
					new_user = User(
						gid=user_data['gid'],
						age=user_data['age'],
						hairColor=user_data['hairColor'],
						isAdmin=user_data['isAdmin']
					)
					
					new_user.put()
					user_dict = new_user.to_dict()
					user_dict['id'] = new_user.key.urlsafe()
					self.response.status = 201
					self.response.write(json.dumps(user_dict))
					self.response.headers['Content-Type'] = 'application/json'
					
				else:
					self.response.status = 400
			
			else:
				self.response.status = 403
		
		except:
			self.response.status = 400
	
	
class UserIdHandler(webapp2.RequestHandler):
	def get(self, id=None):
		try:
			key = ndb.Key(urlsafe=id)
			user = User.get_by_id(key.id())
		
		except:
			self.response.status = 404
			return
			
		try:
			dict = user.to_dict()
			dict['id'] = id
			
			if (not addGoogleInfo(dict, self)):
				dict.pop('gid', None) # Remove google ID from public
			
			self.response.write(json.dumps(dict))
			self.response.headers['Content-Type'] = 'application/json'
								
		except:
			self.response.status = 400
	
	def patch(self, id=None):
		try:
			if(userIsAdmin(self) or isTheUser(self, id)):
				body = self.request.body
				data = json.loads(body)
				
				# Get initial values
				key = ndb.Key(urlsafe=id)
				user = User.get_by_id(key.id())
				
				if data.get('hairColor'):
					user.hairColor = data.get('hairColor')
				if data.get('age'):
					user.age = data.get('age')
				if data.get('isAdmin') and userIsAdmin(self):
					user.isAdmin = data.get('isAdmin')
					
				user.put()
				self.response.status = 204
			
			else:				
				self.response.status = 403
				self.response.write("You are not authorized to access this resource")
			
		except:
			self.response.status = 400

	def delete(self, id=None):
		try:
			if (not userIsAdmin(self)):
				self.response.status = 403
				return
			
			key = ndb.Key(urlsafe=id)
			user = User.get_by_id(key.id())
			
			if not user:
				self.response.status = 400
			
			else:
				user.key.delete()
				self.response.status = 204
		
		except:
			self.response.status = 400
		
		
class ForecastHandler(webapp2.RequestHandler):
	def get(self, id):
		try:
			key = ndb.Key(urlsafe=id)
			house = House.get_by_id(key.id())
		
		except:
			self.response.status = 404
			return
			
		try:
			dict = house.to_dict()
			weather_info = getWeatherInfo(dict['zip'])
			self.response.write(json.dumps(weather_info))
			self.response.headers['Content-Type'] = 'application/json'
			
		except:
			self.response.status = 400

			
def isTheUser(handler, urlId):
	try:
		userToken = handler.request.headers['Authorization']
		googleId = getGoogleId(userToken)
		
		# Check that the google user id matches the google id in the token
		# First we must obtain the google user ID by querying using the DB ID
		key = ndb.Key(urlsafe=urlId)
		user = User.get_by_id(key.id())
		
		idsMatch = user.gid == googleId
			
		return idsMatch
		
	except:
		return False	

	
def userIsAdmin(handler):
	try:
		userToken = handler.request.headers['Authorization']
		userId = getGoogleId(userToken)
		user = User.query(User.gid == userId).get()
		user_json = ndb_json.dumps(user)
		user_dict = ndb_json.loads(user_json)
		
		return user_dict['isAdmin']
		
	except:
		return False


def getWeatherInfo(zip):
	url = "http://api.openweathermap.org/data/2.5/forecast?zip=" + zip + "&APPID=" + WEATHER_API_KEY
	http = urlfetch.fetch(\
		url=url, \
		method=urlfetch.GET)
	myJson = json.loads(http.content)
	
	return myJson['list']
		
		
class DebugHandler(webapp2.RequestHandler):
	def get(self):
		googleId = "118105365369656868555"
		houses = House.query(House.trackedBy == googleId).fetch()
		house_json = ndb_json.dumps(houses)
		house_dict = ndb_json.loads(house_json)
		
		for i in range(0, House.query(House.trackedBy == googleId).count()):
			house_dict[i]['id'] = houses[i].key.urlsafe()
		
		self.response.write(house_json)
		self.response.headers['Content-Type'] = 'application/json'

		
def addGoogleInfo(dict, handler):
	# Add google+ email if auth token was passed
	try:
		# If the DB ID matches the id in the request, add the email
		userToken = handler.request.headers['Authorization']
		googleId = getGoogleId(userToken)
		
		if (googleId == dict['gid']):
			email = getUserEmail(userToken)
			dict['email'] = email
			return True # signal to parent function not to remove gid
		
		return False # remove gid
		
	except:
		return
		
		
def getUserEmail(token):
	jwt = getJwt(token)
	user_info = verify_id_token(\
		id_token=jwt, \
		audience=AUD)
	
	return user_info['email']
	
	
def getGoogleId(token):
	try:
		jwt = getJwt(token)
		user_info = verify_id_token(\
			id_token=jwt, \
			audience=AUD)
		
		return user_info['sub']
	
	except:
		return
		

def getJwt(token):
	try:
		url = "https://www.googleapis.com/oauth2/v4/token"
		headers = {'Content-Type':'application/x-www-form-urlencoded'}
		payload = { \
			'refresh_token': token, \
			'client_id': CLIENT_ID, \
			'grant_type': 'refresh_token', \
			'client_secret': CLIENT_SECRET
		}
		payload = urllib.urlencode(payload)
		http = urlfetch.fetch(\
			url=url, \
			payload=payload, \
			method=urlfetch.POST, \
			headers=headers)
		
		myJson = json.loads(http.content)
		
		return myJson['id_token']
	
	except:
		return


def getAccessToken(refresh_token):
	try:
		url = "https://www.googleapis.com/oauth2/v4/token"
		headers = {'Content-Type':'application/x-www-form-urlencoded'}
		payload = { \
			'refresh_token': refresh_token, \
			'client_id': CLIENT_ID, \
			'grant_type': 'refresh_token', \
			'client_secret': CLIENT_SECRET
		}
		payload = urllib.urlencode(payload)
		http = urlfetch.fetch(\
			url=url, \
			payload=payload, \
			method=urlfetch.POST, \
			headers=headers)
		
		myJson = json.loads(http.content)
		
		return myJson['access_token']
	
	except:
		return
		

# Deletes all users then adds an admin and non-admin
class SeedUsers(webapp2.RequestHandler):
	def post(self):
		ndb.delete_multi(
			User.query().fetch(keys_only=True)
		)
		new_user = User(
			gid="112755314084608193841",
			age=47,
			hairColor="Brown",
			isAdmin=True
		)
		new_user.put()
		user_dict1 = new_user.to_dict()
		user_dict1['id'] = new_user.key.urlsafe()
		user_dict1['token'] = ADMIN_TOKEN
					
		new_user = User(
			gid="118105365369656868555",
			age=26,
			hairColor="Blonde",
			isAdmin=False
		)
		new_user.put()
		user_dict2 = new_user.to_dict()
		user_dict2['id'] = new_user.key.urlsafe()
		user_dict2['token'] = NONADMIN_TOKEN
		
		output = [user_dict1, user_dict2]
		self.response.status = 201
		self.response.write(json.dumps(output))
		self.response.headers['Content-Type'] = 'application/json'
		

# Deletes all houses then adds some
class SeedHouses(webapp2.RequestHandler):
	def post(self):
		ndb.delete_multi(
			House.query().fetch(keys_only=True)
		)
		new_house = House(
			address="556 Main Street",
			price="284500",
			trackedBy="112755314084608193841",
			zip="97201"
		)
		new_house.put()
		house_dict1 = new_house.to_dict()
		house_dict1['id'] = new_house.key.urlsafe()
					
		new_house = House(
			address="900 12th Street",
			price="198000",
			trackedBy="118105365369656868555",
			zip="97340"
		)
		new_house.put()
		house_dict2 = new_house.to_dict()
		house_dict2['id'] = new_house.key.urlsafe()
		house_dict2['token'] = NONADMIN_TOKEN
		
		new_house = House(
			address="123 ABC Street",
			price="1234500",
			trackedBy="118105365369656868555",
			zip="97342"
		)
		new_house.put()
		house_dict3 = new_house.to_dict()
		house_dict3['id'] = new_house.key.urlsafe()
		house_dict3['token'] = NONADMIN_TOKEN
		
		output = [house_dict1, house_dict2, house_dict3]
		self.response.status = 201
		self.response.write(json.dumps(output))
		self.response.headers['Content-Type'] = 'application/json'


class AuthHandler(webapp2.RequestHandler):
	def get(self):
		flow = flow_from_clientsecrets('client_secrets.json',
				scope='https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
				redirect_uri='http://localhost:8080/auth-callback')
		
		auth_uri = flow.step1_get_authorize_url()
		webapp2.redirect(str(auth_uri))
		self.response.write(auth_uri)


class CallbackHandler(webapp2.RequestHandler):
	def get(self):
		self.response.write("excellent work smithers....")
	
	
class Main(webapp2.RequestHandler):
    def get(self):
        self.response.write("excellent!!!")

		
allowed_methods = webapp2.WSGIApplication.allowed_methods
new_allowed_methods = allowed_methods.union(('PATCH',))
webapp2.WSGIApplication.allowed_methods = new_allowed_methods
app = webapp2.WSGIApplication([
    ('/', Main),
	('/auth', AuthHandler),
	('/auth-callback', CallbackHandler),
	('/debug', DebugHandler),
	('/seedUsers', SeedUsers),
	('/seedHouses', SeedHouses),
	('/users', UserHandler),
	('/users/(.*)', UserIdHandler),
	('/houses', HouseHandler),
	('/houses/(.*)/forecast', ForecastHandler),
	('/houses/(.*)', HouseIdHandler),
], debug=True)