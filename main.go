package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

// --- Estruturas de Dados para Comunicação com Frontend ---
type AuthPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UpdatePayload struct {
	SheetName string `json:"sheetName"`
	Row       int    `json:"row"` 
	Col       int    `json:"col"` 
	Value     string `json:"value"`
}

type NFeImportPayload struct {
	XMLContent string `json:"xmlContent"` 
}

// --- Variáveis Globais de Serviço ---
var srv *sheets.Service
var spreadsheetID = os.Getenv("SPREADSHEET_ID") 

// JWT_SECRET deve ser lido de ENV para gerar/validar tokens de sessão
var jwtSecret = os.Getenv("JWT_SECRET") 

// --- Configuração e Inicialização ---

func initSheetsService() *sheets.Service {
	ctx := context.Background()

	// LÊ AS CREDENCIAIS DO GOOGLE DE UMA VARIÁVEL DE AMBIENTE (RECOMENDADO PARA RENDER)
	// A variável deve ser 'GOOGLE_CREDENTIALS_JSON' e conter o JSON inteiro em uma linha.
	credsJSON := os.Getenv("GOOGLE_CREDENTIALS_JSON")
	if credsJSON == "" {
		log.Fatal("A variável de ambiente GOOGLE_CREDENTIALS_JSON não está configurada.")
	}
	
	config, err := google.JWTConfigFromJSON([]byte(credsJSON), sheets.SpreadsheetsScope)
	if err != nil {
		log.Fatalf("Erro ao criar config JWT: %v", err)
	}
	client := config.Client(ctx)
	
	sheetsSrv, err := sheets.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Erro ao criar serviço Sheets: %v", err)
	}
	log.Println("Serviço do Google Sheets inicializado.")
	return sheetsSrv
}

func main() {
	if spreadsheetID == "" || jwtSecret == "" {
		log.Fatal("Variáveis de ambiente SPREADSHEET_ID e JWT_SECRET devem ser definidas.")
	}
	srv = initSheetsService()

	// --- Configuração das Rotas (Endpoints) ---
	
	// Cria um multiplexador para aplicar middlewares
	mux := http.NewServeMux()

	// Aplica o middleware de CORS e, em seguida, o de Autenticação (para rotas protegidas)
	
	// Rotas Públicas
	mux.HandleFunc("/api/login", enableCORS(handleLogin))
	
	// Rotas Protegidas (aplicamos o middleware de autenticação)
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/data", handleGetData)
	protectedMux.HandleFunc("/api/update", handleUpdateCell)
	protectedMux.HandleFunc("/api/importar-xml", handleImportXML)
	protectedMux.HandleFunc("/api/importar-chave", handleImportChave)
	protectedMux.HandleFunc("/api/apagar", handleClearSheets)
	
	// Todas as rotas protegidas passam por 'authenticate' antes de 'enableCORS'
	mux.Handle("/api/", enableCORS(authenticate(protectedMux.ServeHTTP)))


	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Servidor Go API rodando na porta :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal("Erro ao iniciar servidor:", err)
	}
}

// --- Middlewares de Segurança ---

// enableCORS é essencial para permitir requisições do Netlify (ou outro domínio)
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Define o domínio do seu Frontend (Netlify/Vercel URL) na variável ALLOWED_ORIGIN
		allowedOrigin := os.Getenv("ALLOWED_ORIGIN")
		if allowedOrigin == "" {
			allowedOrigin = "*" // Usar * apenas em desenvolvimento/teste
		}
		
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400") // Cache por 24 horas

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// authenticate é um mock de middleware de verificação de JWT
func authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Não autorizado: Token não fornecido", http.StatusUnauthorized)
			return
		}
		
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Formato de token inválido", http.StatusUnauthorized)
			return
		}
		
		token := parts[1]
		// AQUI: Lógica REAL de validação do JWT usando 'jwtSecret'
		// Para mock, apenas verificamos se o token existe.
		if token == "mock-jwt-token" {
			// Sucesso: Chama o próximo handler na cadeia
			next(w, r)
			return
		}
		
		http.Error(w, "Token inválido ou expirado", http.StatusUnauthorized)
	}
}


// --- Handlers da API (Mantêm a lógica de negócio) ---

func handleLogin(w http.ResponseWriter, r *http.Request) {
	var payload AuthPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Payload inválido", http.StatusBadRequest)
		return
	}
	
	// Exemplo MOCK de login
	if payload.Username == "admin" && payload.Password == "senha123" {
		// Emita um Token Web JSON (JWT) REAL aqui. Usando mock para o blueprint.
		response := map[string]string{"token": "mock-jwt-token", "user": payload.Username, "expires_in": fmt.Sprintf("%d", time.Now().Add(time.Hour*24).Unix())}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
		return
	}
	
	http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
}

func handleGetData(w http.ResponseWriter, r *http.Request) {
	sheetName := r.URL.Query().Get("sheet")
	if sheetName == "" {
		http.Error(w, "Parâmetro 'sheet' é obrigatório", http.StatusBadRequest)
		return
	}

	readRange := fmt.Sprintf("%s!A1:Z10000", sheetName)
	resp, err := srv.Spreadsheets.Values.Get(spreadsheetID, readRange).Do()
	if err != nil {
		log.Printf("Erro ao ler worksheet %s: %v", sheetName, err)
		http.Error(w, "Erro ao buscar dados da planilha", http.StatusInternalServerError)
		return
	}
	
	// Envie os dados no formato JSON (resp.Values é compatível)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp.Values)
}

func handleUpdateCell(w http.ResponseWriter, r *http.Request) {
	// ... (Lógica de atualização do Sheets usando payload.Row, payload.Col, payload.Value)
	w.WriteHeader(http.StatusOK)
}

func handleImportXML(w http.ResponseWriter, r *http.Request) {
	// ... (Lógica de importação e escrita no Sheets usando payload.XMLContent)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message": "Importação de XML concluída com sucesso"}`))
}

func handleImportChave(w http.ResponseWriter, r *http.Request) {
	// ... (Lógica de importação por chave)
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message": "Importação por chave concluída com sucesso"}`))
}

func handleClearSheets(w http.ResponseWriter, r *http.Request) {
	// ... (Lógica de apagar planilhas)
	w.WriteHeader(http.StatusOK)
}
