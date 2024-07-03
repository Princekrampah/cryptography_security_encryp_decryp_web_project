import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from send_text import send_text_msg
from decouple import config

# Encryption function


def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return b64encode(nonce + tag + ciphertext).decode('utf-8')

# Decryption function


def decrypt_message(encrypted_message, key):
    data = b64decode(encrypted_message.encode('utf-8'))
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode('utf-8')


def generate_key():
    return get_random_bytes(16)


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

    if 'key' not in st.session_state:
        st.session_state.key = None

    if st.button("Generate AES Key"):
        with st.spinner("Generating AES Key..."):
            st.session_state.key = generate_key()
            st.success("AES Key generated!")
            st.error(
                "This is a security risk of exposing the key. Do not expose it to anyone, this is just a demo")
            st.code(b64encode(st.session_state.key).decode('utf-8'))

    if st.session_state.key:
        st.write("Key:")
        st.code(b64encode(st.session_state.key).decode('utf-8'))

    with st.form("cipher_form"):
        text = st.text_area("Enter text here:")
        submit = st.form_submit_button("Submit")

        if submit:
            if encrypt_option and not decrypt_option:
                if st.session_state.key:
                    with st.spinner("Encrypting text..."):
                        result = encrypt_message(
                            text, st.session_state.key)
                        st.warning(
                            "This will be sent as a text message. This is just a demo")
                        st.write("Encrypted text:")
                        st.code(result)
                    with st.spinner("Sending text message..."):
                        send_text_msg(destination=config(
                            "FROM_PHONE_NUMBER"), msg=f"Key: {b64encode(st.session_state.key).decode('utf-8')}\nEncrypted Message: {result}")
                else:
                    st.error("Please generate the AES key first.")
            elif decrypt_option and not encrypt_option:
                if st.session_state.key:
                    try:
                        result = decrypt_message(
                            text, st.session_state.key)
                        st.write("Decrypted text:")
                        st.code(result)
                    except (ValueError, TypeError):
                        st.error(
                            "Invalid encrypted text for decryption. Please ensure it is correct.")
                else:
                    st.error("Please generate the AES key first.")
            else:
                st.error(
                    "Please select either Encrypt or Decrypt, not both or neither.")


if __name__ == "__main__":
    main()
