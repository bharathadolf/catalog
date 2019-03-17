from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from movie_database import Base, Language, Movie, User

#  database and  shortcut for easier database updation
engine = create_engine('sqlite:///moviebase.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Replica user
User1 = User(
    name="First user",
    email="adolfbharath@gmail.com",
    picture="https://lh3.googleusercontent.com"
    "/a-/AAuE7mCt0fDRxjNYA3cwUoqO53uq46g4yVm3lG9epAxkTw=s192")
session.add(User1)
session.commit()

# Telugu Films
language1 = Language(user_id=1, name="Telugu Films")
session.add(language1)
session.commit()

movie1 = Movie(
    user_id=1, name="Kshnam",
    description="Rishi, a San Francisco-based investment banker,\
    comes to India to help Shweta, his ex-girlfriend find her kidnapped child",
    movie_id=1
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Neninthe",
    description="While film director Ravi has to deal with\
    a gangster in order to boost his career,\
    his girlfriend, who is a dancer, has to\
    handle her opportunistic brother-in-law",
    movie_id=1
    )
session.add(movie2)
session.commit()

# Tamil Films
language2 = Language(user_id=1, name="Tamil Films")
session.add(language2)
session.commit()
movie1 = Movie(
    user_id=1,
    name="Ratsasan",
    description="Arun gives up on his dream of becoming\
    a filmmaker and takes up the job of a police officer\
    after his father's death. He then attempts\
    to track down a psycho killer.",
    movie_id=2
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Savarakathi",
    description="Pichai, a barber, has a skirmish\
    with a gangster named Manga while travelling.\
    Pichai runs and goes into hiding when Manga\
    swears to exact revenge before sundown",
    movie_id=2
    )
session.add(movie2)
session.commit()

# Kannada Films
language3 = Language(user_id=1, name="Kannada Films")
session.add(language3)
session.commit()
movie1 = Movie(
    user_id=1, name="The Villain",
    description="A mysterious man, Ram, is being hunted\
    by Ramayya and the police. But a London's don,\
    Kaizen Ram, enters the picture and puzzles them\
    even more when Kaizen and Ram turn out to be \
    two different people",
    movie_id=3
    )
session.add(movie1)
session.commit()
# Malayalam Films
language4 = Language(user_id=1, name="Malayalam Films")
session.add(language4)
session.commit()
movie1 = Movie(
    user_id=1, name="Premam",
    description="While George's first love turns out\
    to be a disappointment, Malar, a college lecturer,\
    rekindles his love interest. His romantic \
    journey takes him through several stages, \
    helping him find his purpose",
    movie_id=4
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Joseph",
    description="Joseph is a 2018 Malayalam-language Indian\
    thriller-drama film directed by M. Padmakumar and \
    written by Shahi Kabir. It stars Joju George, \
    Dileesh Pothan, Irshad, Athmiya, Johny Antony,\
    Sudhi Koppa, Malavika Menon, and Madhuri Braganza",
    movie_id=4
    )
session.add(movie2)
session.commit()

# Hindi Films
language5 = Language(user_id=1, name="Hindi Films")
session.add(language5)
session.commit()
movie1 = Movie(
    user_id=1, name="Dangal",
    description="Mahavir Singh Phogat, a former wrestler,\
    decides to fulfil his dream of winning a gold\
    medal for his country by training his daughters\
    for the Commonwealth Games despite the existing social stigma",
    movie_id=5
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Andhadhun",
    description="Akash, a piano player pretending\
    to be visually-impaired, unwittingly becomes\
    entangled in a number of problems as he \
    witnesses the murder of a former film actor.",
    movie_id=5
    )
session.add(movie2)
session.commit()

# English Films
language6 = Language(user_id=1, name="English Films")
session.add(language6)
session.commit()
movie1 = Movie(
    user_id=1, name="300",
    description="King Leonidas of Sparta and a force\
    of 300 men fight the Persians at Thermopylae in\
    480 B.C.",
    movie_id=6
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Titanic",
    description="A seventeen-year-old aristocrat\
    falls in love with a kind but poor artist \
    aboard the luxurious, ill-fated R.M.S. Titanic.",
    movie_id=6
    )
session.add(movie2)
session.commit()

# Spanish Films
language7 = Language(user_id=1, name="Spanish Films")
session.add(language7)
session.commit()
movie1 = Movie(
    user_id=1, name="The Others",
    description="Grace moves into a new house with \
    her two photosensitive children in Jersey.\
    When a series of inexplicable events occur,\
    Grace starts believing that her house is haunted",
    movie_id=7
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Pan's Labyrinth",
    description="Ofelia moves with her mother to her \
    stepfather's house. At night, a fairy leads her\
    to a faun who informs her that she is a princess\
    and she needs to participate in three tasks to prove her royalty..",
    movie_id=7
    )
session.add(movie2)
session.commit()

# Chinese Films
language8 = Language(user_id=1, name="Chinese Films")
session.add(language8)
session.commit()
movie1 = Movie(
    user_id=1, name="The Great Wall",
    description="After William Garrin, a mercenary,\
    is held captive in prison, he figures a way to\
    defeat the monsters that attack the Great Wall\
    and joins the warriors to protect the region",
    movie_id=8
    )
session.add(movie1)
session.commit()

movie2 = Movie(
    user_id=1, name="Operation Red Sea",
    description="A commando force from the Chinese navy\
    intercepts terrorists and rescues Chinese citizens in Yemen",
    movie_id=8
    )
session.add(movie2)
session.commit()
# Create language of Science Fiction Films
language9 = Language(user_id=1, name="Korean Films")
session.add(language9)
session.commit()
movie1 = Movie(
    user_id=1, name="Train to Busan",
    description="Seok-woo and his daughter are on a train\
    to Busan on the latter's birthday to see his wife.\
    However, the journey turns into a nightmare when\
    they are trapped amidst a zombie outbreak in South Korea",
    movie_id=9
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Snowpiercer",
    description="Survivors of Earth's second Ice Age\
    live out their days on a luxury train that ploughs\
    through snow and ice. The train's poorest residents,\
    who live in the squalid caboose, plan to improve\
    their lot by taking over the engine room",
    movie_id=9
    )
session.add(movie2)
session.commit()

# Nigerian Films
language10 = Language(user_id=1, name="Nigerian Films")
session.add(language10)
session.commit()
movie1 = Movie(
    user_id=1, name="Lionheart",
    description="n order to save her father's ailing\
    bus company, competent but perennially overlooked\
    Adaeze must find a way to work alongside feckless\
    uncle Godswill, in the sharp and comically observed\
    directorial debut from Nollywood star Genevieve Nnaj",
    movie_id=10)
session.add(movie1)
session.commit()

movie2 = Movie(
    user_id=1, name="Half of a Yellow Sun",
    description="Twin sisters (Thandie Newton,\
    Anika Noni Rose) from a wealthy Nigerian\
    family take wildly different paths in life,\
    but both become swept up in the struggle to\
    establish Biafra as an independent republic.",
    movie_id=10
    )
session.add(movie2)
session.commit()

# Westerns
language11 = Language(user_id=1, name="Westerns")
session.add(language11)
session.commit()
movie1 = Movie(
    user_id=1, name="The Good, the Bad and the Ugly",
    description="A bounty hunting scam joins two men\
    in an uneasy alliance against a third in a race\
    to find a fortune in gold buried in a remote cemetery.",
    movie_id=11
    )
session.add(movie1)
session.commit()
movie2 = Movie(
    user_id=1, name="Django Unchained",
    description="With the help of a German bounty\
    hunter, a freed slave sets out to rescue his\
    wife from a brutal Mississippi plantation \
    owner.",
    movie_id=11
    )
session.add(movie2)
session.commit()

print("added language items!")
