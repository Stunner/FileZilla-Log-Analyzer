'''
Created on Jul 10, 2010

@author: Aaron Jubbal
'''

#!/usr/bin/env python
#http://babynamesworld.parentsconnect.com/
#http://babynamesworld.parentsconnect.com/browse-by-a-7.html

import random

class names:
    firstNames =[
                #A
                ['Aaliyah','Aaron','Abagail','Abbey','Abbie','Abbigail','Abby','Abdul','Abdullah','Abel','Abigail','Abigale',\
                'Abigayle','Abraham','Abram','Abril','Acacia','Ace','Ada','Adam','Adamaris','Adan','Addie','Addison','Addyson',\
                'Adelaide','Adele','Adeline','Aden','Adilene','Adin','Aditya','Adolfo','Adonis','Adria','Adrian','Adriana',\
                'Adriane','Adrianna','Adrianne','Adriano','Adriel','Adrien','Adrienne','Aedan','Afton','Agustin','Ahmad','Ahmed',\
                'Aidan','Aiden','Aidyn','Aileen','Aimee','Ainsley','Aisha','Aislinn','Aiyana','Aja','Ajay','Akash','Akasha',\
                'Akeem','Akira','Al','Alaina','Alan','Alana','Alani','Alanna','Alannah','Alayna','Albert','Alberto','Alden',\
                'Aldo','Aleah','Alec','Alecia','Aleena','Alejandra','Alejandro','Alek','Aleksandar','Alena','Alesha','Alessandra',\
                'Alessandro','Alessia','Alex','Alexa','Alexander','Alexandr','Alexandra','Alexandre','Alexandrea','Alexandria',\
                'Alexandro','Alexia','Alexis','Alexus','Alfie','Alfonso','Alfred','Alfredo','Ali','Alia','Alice','Alicia','Alijah',\
                'Alina','Alisa','Alisha','Alison','Alissa','Alivia','Aliya','Aliyah','Aliza','Alize','Allan','Allen','Allie',\
                'Allison','Ally','Allyson','Alma','Alondra','Alonso','Alonzo','Alphonso','Alton','Alvaro','Alvin','Alycia','Alysa',\
                'Alyse','Alysha','Alysia','Alyson','Alyssa','Alyssia','Aman','Amanda','Amandeep','Amani','Amara','Amare','Amari',\
                'Amarion','Amaris','Amaya','Amber','Amberly','Amelia','America','Ami','Amie','Amina','Amir','Amira','Amirah',\
                'Amisha','Amiya','Amiyah','Amos','Amrit','Amy','Amya','Ana','Anabel','Anabelle','Anahi','Anais','Anastasia',\
                'Anaya','Anders','Anderson','Andon','Andrae','Andre','Andrea','Andreas','Andres','Andrew','Andria','Andy','Angel',\
                'Angela','Angelia','Angelica','Angelina','Angeline','Angelique','Angelo','Angie','Angus','Anika','Anisa','Anisha',\
                'Anissa','Anita'],
                ['Billy','Bill','Ben','Benjamin','Bob','Bobby'],
                ['Charles','Carl','Charlie','Clifford','Catalina','Catie','Cat'],
                ['Dillan','David','Dill','Dale','Dane','Doug','Dillbert'],
                ['Earl','Evan'],
                ['Frank'],
                ['George'],
                #J
                ['Jacob','Jonas','Jon','John','Joe','Jill','Jane','Jillian','Jay','Jed'],
                #Z
                ['Zach','Zorro']
                ]
    lastNames = ['Smith','Johnson','Williams','Jones','Brown','Davis','Miller','Wilson','Moore','Taylor','Anderson','Thomas',\
                 'Jackson','White','Harris','Martin','Thompson','Garcia','Martinez','Robinson','Clark','Rodriguez','Lewis','Lee',\
                 'Walker','Hall','Allen','Young','Hernandez','King','Wright','Lopez','Hill','Scott','Green','Adams','Baker',\
                 'Gonzalez','Nelson','Carter''Miller','White','Johnson','Mattew','Wilson','Henderson','Wu','Ming','Yan','Jacobs',\
                 'Lewis','Sanders','Gill','Hanson','Thatcher','Kalnoky','Evans']
    
def getRandFirstAndLast():
    AtoZ = random.randint(0,len(names.firstNames)-1)
    firstName = names.firstNames[AtoZ][random.randint(0,len(names.firstNames[AtoZ])-1)]
    lastName = names.lastNames[random.randint(0,len(names.lastNames)-1)]
    return ' '.join((firstName,lastName))