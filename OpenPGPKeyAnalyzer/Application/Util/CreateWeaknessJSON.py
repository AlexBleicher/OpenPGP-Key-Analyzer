def createWeaknessJSON(name, description, countermeasure):
    weakness = {}
    weakness["Name of Weakness"] = name
    weakness["Description"] = description
    weakness["Countermeasure"] = countermeasure
    return weakness