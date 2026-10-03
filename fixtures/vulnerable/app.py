import pickle
def evaluate_input(user_input):
    return eval(user_input)
def deserialize_input(payload):
    return pickle.loads(payload)
