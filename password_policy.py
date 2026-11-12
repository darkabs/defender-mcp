import string
import secrets

def generate_entra_password(length=12):
    """
    Generates a secure password that strictly complies with the default 
    Microsoft Entra ID password policy requirement (minimum length of 8, 
    and containing at least 3 out of 4 character categories).
    """
    if length < 8 or length > 256:
        raise ValueError("Entra ID password length must be between 8 and 256 characters.")

    # Define the 4 Entra character categories
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits
    symbols = "-@#$%\^&*-_!+=|\\:',.?/~\"();<>"  # Allowed standard symbols
    
    all_categories = [lower, upper, digits, symbols]
    
    while True:
        # 1. Pick 3 out of the 4 categories to guarantee compliance with the 3/4 rule
        selected_categories = secrets.SystemRandom().sample(all_categories, 3)
        
        # 2. Start the password with 1 guaranteed character from each chosen category
        password_chars = [secrets.choice(cat) for cat in selected_categories]
        
        # 3. Fill the remaining length with characters from ALL 4 categories combined
        combined_pool = "".join(all_categories)
        password_chars += [secrets.choice(combined_pool) for _ in range(length - 3)]
        
        # 4. Shuffle securely to randomize the positions of the initial deterministic characters
        secrets.SystemRandom().shuffle(password_chars)
        password = "".join(password_chars)
        
        # 5. Verify the final password meets the Entra ID 3-of-4 category validation rule
        has_lower = any(c in lower for c in password)
        has_upper = any(c in upper for c in password)
        has_digit = any(c in digits for c in password)
        has_symbol = any(c in symbols for c in password)
        
        # Count how many categories are satisfied
        categories_satisfied = sum([has_lower, has_upper, has_digit, has_symbol])
        
        if categories_satisfied >= 3:
            return password

# # Generate a compliant 14-character password
# new_password = generate_entra_password(length=14)
# print(f"Generated Entra-compliant password: {new_password}")
