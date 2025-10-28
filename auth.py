import os
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from models import Usuario
from database import get_db

SECRET_KEY = os.getenv("SECRET_KEY", "um-segredo-muito-forte")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def criar_hash_senha(senha: str) -> str:
    return pwd_context.hash(senha)

def verificar_senha(senha: str, senha_hash: str) -> bool:
    return pwd_context.verify(senha, senha_hash)

def criar_token_acesso(data: dict, expira: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expira or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def autenticar_usuario(db: Session, nome: str, senha: str) -> Optional[Usuario]:
    usuario = db.query(Usuario).filter(Usuario.nome == nome).first()
    if usuario and verificar_senha(senha, usuario.senha_hash):
        return usuario
    return None

def obter_usuario_logado(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Usuario:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não autorizado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        nome_usuario: str = payload.get("sub")
        if nome_usuario is None:
            raise cred_exc
    except JWTError:
        raise cred_exc
    usuario = db.query(Usuario).filter(Usuario.nome == nome_usuario).first()
    if usuario is None:
        raise cred_exc
    return usuario
