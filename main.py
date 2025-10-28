from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
import models, schemas, database, auth
from routers import livros, autores, categorias, editoras
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="API Livraria Digital",
    version="1.0.0",
    description="CRUD completo para gestão de livros, autores, editoras e categorias. Protegido por autenticação JWT."
)

origins = [
    "http://localhost:3000",
    "http://localhost:8080"
    # Adicione outros domínios conforme necessidade
]

#     allow_origins=["*"], origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

database.init_db()
app.include_router(livros.router)
app.include_router(autores.router)
app.include_router(categorias.router)
app.include_router(editoras.router)

@app.post("/usuarios", response_model=schemas.UsuarioOut, status_code=201)
def criar_usuario(usuario: schemas.UsuarioCreate, db: Session = Depends(database.get_db)):
    hashed = auth.criar_hash_senha(usuario.senha)
    novo_usuario = models.Usuario(nome=usuario.nome, email=usuario.email, senha_hash=hashed)
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)
    return novo_usuario

from fastapi.security import OAuth2PasswordRequestForm

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db)):
    usuario = auth.autenticar_usuario(db, form_data.username, form_data.password)
    if not usuario:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")
    token = auth.criar_token_acesso(data={"sub": usuario.nome})
    return {"access_token": token, "token_type": "bearer"}
