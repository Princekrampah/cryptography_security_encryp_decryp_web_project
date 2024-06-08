import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import hexlify, unhexlify
from send_text import send_text_msg
from decouple import config

# Encryption function


def encrypt_message(message, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return hexlify(encrypted_message).decode()

# Decryption function


def decrypt_message(encrypted_message, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(
        unhexlify(encrypted_message.encode()))
    return decrypted_message.decode("utf-8")


def generate_keys():
    key = RSA.generate(1024)
    st.session_state.private_key = key
    st.session_state.public_key = key.publickey()


def main():
    st.sidebar.title("Options")
    encrypt_option = st.sidebar.checkbox("Encrypt")
    decrypt_option = st.sidebar.checkbox("Decrypt")

    # Group member Details
    st.sidebar.markdown("### Group Members:balloon:")
    st.sidebar.markdown("1. Vanessa")
    st.sidebar.markdown("2. Conrad")
    st.sidebar.markdown("3. Prince")
    st.sidebar.markdown("4. Elvis")

    st.title("Encrypt / Decrypt Text")

    if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
        st.session_state.private_key = None
        st.session_state.public_key = None

    if st.button("Generate RSA Key Pair"):
        with st.spinner("Generating RSA Key Pair..."):
            generate_keys()
            st.success("RSA Key Pair generated!")
            st.error(
                "This is a security risk of exposing the private key. Do not expose it to anyone, this is just a demo")
            st.code(st.session_state.private_key.export_key().decode())

    if st.session_state.public_key:
        st.write("Public Key:")
        st.code(st.session_state.public_key.export_key().decode())

    with st.form("cipher_form"):
        text = st.text_area("Enter text here:")
        submit = st.form_submit_button("Submit")

        if submit:
            if encrypt_option and not decrypt_option:
                if st.session_state.public_key:
                    with st.spinner("Encrypting text..."):
                        result = encrypt_message(
                            text, st.session_state.public_key)
                        st.warning(
                            "This will be sent as a text message. This is just a demo")
                        st.write("Encrypted text:")
                        st.code(result)
                    with st.spinner("Sending text message..."):
                        send_text_msg(destination=config(
                            "FROM_PHONE_NUMBER"), msg=f"Public Key: {st.session_state.public_key.export_key().decode()}\nEncrypted Message: {result}")
                else:
                    st.error("Please generate the RSA key pair first.")
            elif decrypt_option and not encrypt_option:
                if st.session_state.private_key:
                    try:
                        result = decrypt_message(
                            text, st.session_state.private_key)
                        st.write("Decrypted text:")
                        st.code(result)
                    except (ValueError, TypeError):
                        st.error(
                            "Invalid encrypted text for decryption. Please ensure it is correct.")
                else:
                    st.error("Please generate the RSA key pair first.")
            else:
                st.error(
                    "Please select either Encrypt or Decrypt, not both or neither.")


if __name__ == "__main__":
    main()
