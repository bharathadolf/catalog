# IMPORT SECTION
from flask import Flask, render_template, request
from flask import redirect, url_for, jsonify, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from movie_database import Language, Base, Movie, User
from flask import session as login_session
import random
import string
import json

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests


# CONNECTIONS OF APPLICATION
app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Movie Catalogue"
engine = create_engine(
    'sqlite:///moviebase.db',
    connect_args={'check_same_thread': False}, echo=True)
Base.metadata.bind = engine

DBsession = sessionmaker(bind=engine)
session = DBsession()


@app.route('/login/')
# This function is used for login view of user
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in range(32))
    login_session['state'] = state
    language = session.query(Language).all()
    movie = session.query(Movie).all()
    return render_template('login.html', STATE=state,
                           language=language, movie=movie)


# If user already logged or not
@app.route('/gconnect', methods=['POST'])
# Connect to Google account using this function
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid State parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID doesn't match app's."), 401)
        print("Token's client ID doesn't match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
                                 json.dumps(
                                            'Current user already connected'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<center><h2><font color="green">Welcome '
    output += login_session['username']
    output += '!</font></h2></center>'
    output += '<center><img src="'
    output += login_session['picture']
    output += ' " style = "width: 200px; -webkit-border-radius: 200px;" '
    output += ' " style = "height: 200px;border-radius: 200px;" '
    output += ' " style = "-moz-border-radius: 200px;"></center>" '
    flash("You are logged as %s" % login_session['username'])
    print("Done")
    return output

# User creation function using login session as arguement


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# Function for Acquiring user information
def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

# Function for getting user id which is a token for user ,email as argument


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as e:
        return None

# JSON functions


@app.route('/language/JSON')
def languageJSON():
    language = session.query(Language).all()
    return jsonify(language=[c.serialize for c in language])


@app.route('/language/<int:language_id>/main/<int:movie_id>/JSON')
def languageListJSON(language_id, movie_id):
    movie_list = session.query(Movie).filter_by(id=movie_id).one()
    return jsonify(Movie_List=Movie_list.serialize)


@app.route('/language/<int:movie_id>/main/JSON')
def movieListJSON(movie_id):
    language = session.query(Language).filter_by(id=movie_id).one()
    movie = session.query(Movie).filter_by(movie_id=language.id).all()
    return jsonify(MovieList=[i.serialize for i in movie])


# Entire project home page

@app.route('/language/')
# For viewing of language function
def showLanguage():
    language = session.query(Language).all()
    return render_template('language.html', language=language)


@app.route('/language/new/', methods=['GET', 'POST'])
# Function for creating a new language
def newLanguage():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newLanguage = Language(
            name=request.form['name'], user_id=login_session['user_id']
            )
        session.add(newLanguage)
        session.commit()
        return redirect(url_for('showLanguage'))
    else:
        return render_template('newLanguage.html')


@app.route('/language/<int:language_id>/edit/', methods=['GET', 'POST'])
# Function for editing language
def editLanguage(language_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedLanguage = session.query(Language).filter_by(id=language_id).one()
    creater_id = getUserInfo(editedLanguage.user_id)
    user_id = getUserInfo(login_session['user_id'])
    if creater_id.id != login_session['user_id']:
        flash(
            "you can't edit this language"
            "Because it belongs to %s" % (creater_id.name)
            )
        return redirect(url_for('showLanguage'))
    if request.method == 'POST':
        if request.form['name']:
            editedLanguage.name = request.form['name']
            flash("language Successfully Edited %s" % (editedLanguage.name))
            return redirect(url_for('showLanguage'))
    else:
        return render_template('editLanguage.html', language=editedLanguage)


@app.route('/language/<int:language_id>/delete/', methods=['GET', 'POST'])
# This function is used deleting language -function dependant on parent info
def deleteLanguage(language_id):
    if 'username' not in login_session:
        return redirect('/login')
    languageToDelete = session.query(
        Language).filter_by(id=language_id).one()
    creater_id = getUserInfo(languageToDelete.user_id)
    user_id = getUserInfo(login_session['user_id'])
    if creater_id.id != login_session['user_id']:
        flash("you can't delete this language"
              "Because it belongs to %s" % (creater_id.name))
        return redirect(url_for('showLanguage'))
    if request.method == 'POST':
        session.delete(languageToDelete)
        flash("Successfully Deleted %s" % (languageToDelete.name))
        session.commit()
        return redirect(url_for('showLanguage', language_id=language_id))
    else:
        return render_template(
            'deleteLanguage.html', language=languageToDelete
            )


@app.route('/language/<int:language_id>/movies/')
# This function is used for viewing of movies in a list manner
def showMovies(language_id):
    language = session.query(Language).filter_by(id=language_id).one()
    movie = session.query(Movie).filter_by(movie_id=language_id).all()
    return render_template('main.html', language=language, movie=movie)


@app.route('/language/<int:movie_id>/new/', methods=['GET', 'POST'])
# This function is used for creating new movies list
def newMovieList(movie_id):
    if 'username' not in login_session:
        return redirect('login')
    language = session.query(Language).filter_by(id=movie_id).one()
    creater_id = getUserInfo(language.user_id)
    user_id = getUserInfo(login_session['user_id'])
    if creater_id.id != login_session['user_id']:
        flash("you can't add this movie"
              "Because it belongs to %s" % (creater_id.name))
        return redirect(url_for('showLanguage', language_id=movie_id))
    if request.method == 'POST':
        newList = Movie(
            name=request.form['name'],
            description=request.form['description'],
            movie_id=movie_id,
            user_id=login_session['user_id'])
        session.add(newList)
        session.commit()
        flash("New movie List %s is created" % (newList))
        return redirect(url_for('showMovies', language_id=movie_id))
    else:
        return render_template('newmovie.html', movie_id=movie_id)


@app.route('/language/<int:language_id>/<int:b_id>/edit/',
           methods=['GET', 'POST'])
# This function for editing movie list -function on child editing file
def editMovieList(language_id, b_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(Movie).filter_by(id=b_id).one()
    language = session.query(Language).filter_by(id=language_id).one()
    creater_id = getUserInfo(editedItem.user_id)
    user_id = getUserInfo(login_session['user_id'])
    if creater_id.id != login_session['user_id']:
        flash("you can't edit this language"
              "Because it belongs to %s" % (creater_id.name))
        return redirect(url_for('showMovies', language_id=language_id))
    if request.method == 'POST':
        editedItem.name = request.form['name']
        editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash("movie List has been edited!")
        return redirect(url_for('showMovies', language_id=language_id))
    else:
        return render_template('editmovie.html',
                               language=language, movie=editedItem)


@app.route('/language/<int:movie_id>/<int:list_id>/delete/',
           methods=['GET', 'POST'])
# This function is used for deleting the movie
def deleteMovieList(movie_id, list_id):
    if 'username' not in login_session:
        return redirect('/login')
    language = session.query(Language).filter_by(id=movie_id).one()
    listToDelete = session.query(Movie).filter_by(id=list_id).one()
    creater_id = getUserInfo(listToDelete.user_id)
    user_id = getUserInfo(login_session['user_id'])
    if creater_id.id != login_session['user_id']:
        flash("you can't edit this language"
              "Because it belongs to %s" % (creater_id.name))
        return redirect(url_for('showMovies', language_id=movie_id))
    if request.method == 'POST':
        session.delete(listToDelete)
        session.commit()
        flash("movie list has been Deleted!!!")
        return redirect(url_for('showMovies', language_id=movie_id))
    else:
        return render_template('deletemovie.html', lists=listToDelete)


@app.route('/disconnect')
# This function for logout session of user
def logout():
    access_token = login_session['access_token']
    print("In gdisconnect access_token is %s", access_token)
    print("User name is:")
    print(login_session['username'])

    if access_token is None:
        print("Access Token is None")
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = login_session['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(uri=url, method='POST', body=None,
                       headers={'Content-Type':
                                'application/x-www-form-urlencoded'})[0]
    print(result['status'])
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash("Successfully logged out")
        return redirect(url_for('showLanguage'))
    else:
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
