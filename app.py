from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

from flask_cors import CORS
CORS(app)

from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app.config['JWT_SECRET_KEY'] = 'segredo_super_secreto'  # Troque depois por algo seguro
jwt = JWTManager(app)

# Configuração do banco SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///usuarios.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Modelo Usuario
from werkzeug.security import generate_password_hash, check_password_hash

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)

    def set_senha(self, senha):
        self.senha_hash = generate_password_hash(senha)

    def verificar_senha(self, senha):
        return check_password_hash(self.senha_hash, senha)

    def to_dict(self):
        return {"id": self.id, "nome": self.nome, "email": self.email}

from marshmallow import Schema, fields

class UsuarioSchema(Schema):
    id = fields.Int(dump_only=True)
    nome = fields.Str(required=True)
    email = fields.Email(required=True)
    senha = fields.Str(required=True, load_only=True)

# Criar o banco de dados (apenas na primeira vez)
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return 'API de Usuários com banco de dados!'

from flask_jwt_extended import jwt_required

@app.route('/usuarios', methods=['GET', 'POST'])
def gerenciar_usuarios():
    if request.method == 'GET':
        return listar_usuarios()

    if request.method == 'POST':
        return cadastrar_usuario()

@jwt_required()
def listar_usuarios():
    usuarios = Usuario.query.all()
    return jsonify([u.to_dict() for u in usuarios])

def cadastrar_usuario():
    schema = UsuarioSchema()
    try:
        dados = schema.load(request.get_json())
    except Exception as e:
        return jsonify({"erro": str(e)}), 400

    if Usuario.query.filter_by(email=dados['email']).first():
        return jsonify({"erro": "E-mail já cadastrado"}), 409

    novo = Usuario(
        nome=dados['nome'],
        email=dados['email']
    )
    novo.set_senha(dados['senha'])

    db.session.add(novo)
    db.session.commit()
    return jsonify(schema.dump(novo)), 201    

@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()
    print("📥 Dados recebidos:", dados)

    usuario = Usuario.query.filter_by(email=dados['email']).first()

    if usuario:
        print(f"✅ Usuário encontrado: {usuario.email}")
        print(f"🔍 Hash salvo: {usuario.senha_hash}")

        if usuario.verificar_senha(dados['senha']):
            print("🔐 Senha correta!")
            token = create_access_token(identity=str(usuario.id))
            return jsonify({"token": token})
        else:
            print("❌ Senha incorreta!")

    else:
        print("❌ Usuário não encontrado.")

    return jsonify({"erro": "Email ou senha inválidos"}), 401
    
@app.route('/usuarios/<int:id>', methods=['GET', 'PUT', 'DELETE'])
def usuario_por_id(id):
    usuario = Usuario.query.get(id)

    if not usuario:
        return jsonify({"erro": "Usuário não encontrado"}), 404

    if request.method == 'GET':
        return jsonify(usuario.to_dict())

    if request.method == 'PUT':
        dados = request.get_json()
        usuario.nome = dados.get('nome', usuario.nome)
        usuario.email = dados.get('email', usuario.email)
        db.session.commit()
        return jsonify({"mensagem": "Usuário atualizado com sucesso"})

    if request.method == 'DELETE':
        db.session.delete(usuario)
        db.session.commit()
        return jsonify({"mensagem": "Usuário deletado com sucesso"})

@app.route('/debug-usuarios')
def debug_usuarios():
    usuarios = Usuario.query.all()
    return jsonify([u.to_dict() for u in usuarios])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
