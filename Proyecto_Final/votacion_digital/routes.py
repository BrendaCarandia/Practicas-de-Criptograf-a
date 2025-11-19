from flask import render_template, url_for, flash, redirect, request, send_file, jsonify
from app import app, db, login_manager, authority_private_key, authority_public_key
from forms import RegistrationForm, LoginForm
from models import User, BlindSignatureToken, Vote
from flask_login import login_user, current_user, logout_user, login_required
from crypto_utils import (generate_rsa_key_pair, encrypt_private_key, decrypt_private_key,
                          blind_message, sign_blinded_message, unblind_signature,
                          verify_blind_signature, hash_message_to_int, sign_message,
                          verify_signature)
import io # Para manejar archivos en memoria 
from datetime import datetime
from collections import Counter

AVAILABLE_VOTE_OPTIONS = ['Candidato A', 'Candidato B', 'Candidato C', 'Candidato D']

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', title='Inicio')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, user_type=form.user_type.data)
        user.set_password(form.password.data) # Esto ahora usa SHAke128 y genera sal

        # Si es un usuario convencional, generar y almacenar llaves RSA
        if user.user_type == 'conventional':
            private_key_pem, public_key_pem = generate_rsa_key_pair()
            user.public_key = public_key_pem
            # Encriptar la clave privada con la contraseña del usuario
            # (o una clave derivada de ella)
            # NOTA: La contraseña en texto plano solo está disponible aquí.
            # Es crucial usarla de forma segura y no almacenarla.
            user.private_key_encrypted = encrypt_private_key(private_key_pem, form.password.data)

        db.session.add(user)
        db.session.commit()
        flash(f'¡Cuenta creada para {form.username.data}! Ahora puedes iniciar sesión.', 'success')

        # Si es usuario convencional, ofrecer descarga de la clave pública
        if user.user_type == 'conventional':
            # Almacenamos el PEM de la clave pública en la sesión para la descarga
            # Esto es una simplificación; en un sistema real, se gestionaría de otra manera
            # para evitar almacenar datos sensibles en la sesión por mucho tiempo.
            # Para este proyecto, lo hacemos para que el usuario pueda descargarla justo después del registro.
            # No la descargaremos aquí directamente, sino que redirigiremos a una ruta de descarga.
            return redirect(url_for('download_public_key', user_id=user.id))
        else:
            return redirect(url_for('login'))
    return render_template('register.html', title='Registro', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data): # Ahora usa SHAke128
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(next_page or url_for('dashboard')) # Redirigir al dashboard
        else:
            flash('Inicio de sesión fallido. Por favor, verifica tu nombre de usuario y contraseña.', 'danger')
    return render_template('login.html', title='Iniciar Sesión', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.user_type == 'admin':
        # Obtener estadísticas de votación
        all_votes = Vote.query.all()
        total_votes = len(all_votes)
        vote_counts = Counter(vote.vote_option for vote in all_votes)
        # Convertira formato de lista de diccionarios para la plantilla
        statistics = [{'option': option, 'count': count} for option, count in vote_counts.items()]
        # Ordenar estadísticas por número de votos descendente
        statistics.sort(key=lambda x: x['count'], reverse=True)
        return render_template('admin_dashboard.html', title='Panel de Administrador', statistics=statistics, total_votes=total_votes)
    else:
        # Obtener votaciones realizadas por el usuario
        user_votes = Vote.query.filter_by(user_id=current_user.id).all()
        # Obtener tokens de firma ciega del usuario
        pending_tokens = BlindSignatureToken.query.filter_by(user_id=current_user.id, is_used=False).all()
        return render_template('user_dashboard.html', title='Panel de Usuario', user_votes=user_votes, pending_tokens=pending_tokens, available_options=AVAILABLE_VOTE_OPTIONS)
    

@app.route("/request_blind_signature_token", methods=['POST'])
@login_required
def request_blind_signature_token():
    if current_user.user_type != 'conventional':
        return jsonify({'status': 'error', 'message': 'Solo los usuarios convencionales pueden solicitar tokens de firma ciega.'}), 403

    # Verificar si el usuario ya ha votado (a través de cualquier token)
    existing_vote = Vote.query.filter_by(user_id=current_user.id).first()
    if existing_vote:
        return jsonify({'status': 'error', 'message': 'Ya has emitido tu voto. Solo se permite un voto por usuario.'}), 403

    data = request.get_json()
    vote_option = data.get('vote_option')

    if not vote_option:
        return jsonify({'status': 'error', 'message': 'Opción de voto no proporcionada.'}), 400

    # Hash del mensaje de voto (lo que queremos firmar ciegamente)
    message_hash_int = hash_message_to_int(vote_option)
    message_hash_str = str(message_hash_int) # Para almacenar en DB

    # Verificar si el usuario ya tiene un token para este hash o si ya votó
    existing_token = BlindSignatureToken.query.filter_by(user_id=current_user.id, message_hash=message_hash_str).first()
    if existing_token and existing_token.is_used:
        return jsonify({'status': 'error', 'message': 'Ya has votado con esta opción o tienes un token usado.'}), 400
    elif existing_token and not existing_token.is_used:
        return jsonify({'status': 'error', 'message': 'Ya tienes un token de firma ciega pendiente para esta opción. Utilízalo.',
                        'signature_token': existing_token.signature_token,
                        'vote_option': vote_option}), 200

    # --- Proceso de Firma Ciega en el servidor (simplificado) ---
    # 1. Cegar el mensaje
    blinded_message_int, r = blind_message(message_hash_int, authority_public_key)

    # 2. Firmar el mensaje cegado con la clave privada de la autoridad
    signed_blinded_message_int = sign_blinded_message(blinded_message_int, authority_private_key)

    # 3. Descegar la firma
    unblinded_signature_int = unblind_signature(signed_blinded_message_int, r, authority_public_key)

    # 4. Verificar la firma descegada (opcional, para asegurar que todo salió bien)
    if not verify_blind_signature(message_hash_int, unblinded_signature_int, authority_public_key):
        return jsonify({'status': 'error', 'message': 'Error interno al generar la firma ciega.'}), 500

    # Guardar el token de firma ciega en la base de datos
    # Almacenamos el hash del mensaje y la firma descegada como token
    #new_token = BlindSignatureToken(user_id=current_user.id, 
    #                                message_hash=message_hash_str,
    #                                signature_token=str(unblinded_signature_int)) # Almacenamos como string
   # db.session.add(new_token)
   # db.session.commit()

    try:
        new_token = BlindSignatureToken(
            user_id=current_user.id,
            message_hash=message_hash_str,
            signature_token=str(unblinded_signature_int),
            is_used=False
        )
        db.session.add(new_token)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Token de firma ciega generado exitosamente.',
            'signature_token': str(unblinded_signature_int),
            'vote_option': vote_option
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error al generar el token: {str(e)}'
        }), 500

@app.route("/submit_vote", methods=['POST'])
@login_required
def submit_vote():
    if current_user.user_type != 'conventional':
        flash('Solo los usuarios convencionales pueden emitir votos.', 'danger')
        return jsonify({'status': 'error', 'message': 'Acceso no autorizado.'}), 403

    data = request.get_json()
    vote_option = data.get('vote_option')
    signature_token_str = data.get('signature_token')
    private_key_password = data.get('private_key_password') # Contraseña para desencriptar la clave privada del usuario
    user_public_key_pem = data.get('user_public_key_pem') # Clave pública del usuario para verificar la firma final

    if not all([vote_option, signature_token_str, private_key_password, user_public_key_pem]):
        return jsonify({'status': 'error', 'message': 'Faltan datos para enviar el voto.'}), 400

    # Convertir la firma token a entero
    try:
        signature_token_int = int(signature_token_str)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Formato de token de firma inválido.'}), 400

    # Verificar el token de firma ciega
    message_hash_int = hash_message_to_int(vote_option)
    message_hash_str = str(message_hash_int)

    # 1. Verificar que el token exista y no haya sido usado
    token = BlindSignatureToken.query.filter_by(user_id=current_user.id, message_hash=message_hash_str).first()
    if not token:
        return jsonify({'status': 'error', 'message': 'No se encontró un token de firma ciega para esta opción de voto.'}), 403
    if token.is_used:
        return jsonify({'status': 'error', 'message': 'Este token de firma ciega ya ha sido utilizado para votar.'}), 403

    # 2. Verificar que la firma ciega descegada sea válida para el mensaje
    if not verify_blind_signature(message_hash_int, signature_token_int, authority_public_key):
        return jsonify({'status': 'error', 'message': 'El token de firma ciega es inválido.'}), 403

    # 3. Desencriptar la clave privada del usuario para firmar el voto final
    decrypted_private_key_pem = decrypt_private_key(current_user.private_key_encrypted, private_key_password)
    if not decrypted_private_key_pem:
        return jsonify({'status': 'error', 'message': 'Contraseña de clave privada incorrecta.'}), 401

    # 4. Firmar el voto final con la clave privada del usuario
    # Aquí, el mensaje que firma el usuario es el hash del voto Y el token de firma ciega,
    # para vincularlos y demostrar que el token fue usado para este voto.
    # Esto es una capa adicional de seguridad/verificación.
    message_to_sign_by_user = f"{vote_option}-{signature_token_str}"
    final_user_signature = sign_message(decrypted_private_key_pem, message_to_sign_by_user, private_key_password)

    # 5. Usar la clave pública del usuario para verificar la firma (opcional)
    if not verify_signature(user_public_key_pem, message_to_sign_by_user, final_user_signature):
        return jsonify({'status': 'error', 'message': 'Error al verificar la firma del voto con la clave pública del usuario.'}), 500

    # 6. Guardar el voto en la base de datos
    new_vote = Vote(user_id=current_user.id,
                    vote_option=vote_option,
                    signature=final_user_signature, # Almacenamos la firma del usuario
                    timestamp=datetime.utcnow())
    db.session.add(new_vote)

    # Marcar el token como usado
    token.is_used = True
    db.session.commit()

    flash('¡Tu voto ha sido registrado exitosamente!', 'success')
    return jsonify({'status': 'success', 'message': 'Voto registrado exitosamente.'}), 200

# Ruta para descargar la clave pública del usuario (ya existente, pero la incluí para contexto)
@app.route("/download_public_key/<int:user_id>")
@login_required
def download_public_key(user_id):
    if current_user.id != user_id or current_user.user_type != 'conventional':
        flash('No tienes permiso para descargar esta clave.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    if not user.public_key:
        flash('Este usuario no tiene una clave pública asignada.', 'danger')
        return redirect(url_for('dashboard'))

    key_file = io.BytesIO(user.public_key.encode('utf-8'))
    filename = f"{user.username}_public.pem"

    return send_file(key_file,
                     mimetype='application/x-pem-file',
                     as_attachment=True,
                     download_name=filename)

# Nueva ruta para obtener las opciones de voto
@app.route("/get_vote_options")
@login_required
def get_vote_options():
    return jsonify(AVAILABLE_VOTE_OPTIONS)