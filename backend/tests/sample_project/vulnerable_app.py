
# ARGUS Security Testing Sample
# These vulnerabilities are intentional.

password = "admin123"

user_input = input("Enter an expression: ")

result = eval(user_input)

print("Result:", result)

