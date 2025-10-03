package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	// CORS library (CORREÇÃO CRÍTICA PARA FUNCIONAR ONLINE)
	"github.com/rs/cors"
	
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

// --- Estruturas e Variáveis Globais (APENAS para o Servidor) ---

var sheetsService *sheets.Service

// Estrutura para a requisição do Frontend
type XMLRequest struct {
	XMLContent string `json:"xml_content"` // Conteúdo do XML da Nota Fiscal (string)
	UserID string `json:"user_id"`
}

// Estruturas simplificadas para NF-e
type NFe struct {
	XMLName xml.Name `xml:"NFe"`
	InfNFe  struct {
		ID  string `xml:"Id,attr"` // chave da nota (ex: NFe4321...)
		Det []struct {
			Prod struct {
				CProd string `xml:"cProd"`
				CEAN  string `xml:"cEAN"`
				XProd string `xml:"xProd"`
				QCom  string `xml:"qCom"`
			} `xml:"prod"`
			NItem string `xml:"nItem,attr"` // novo campo Item
		} `xml:"det"`
	} `xml:"infNFe"`
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	
	// Inicializa o cliente do Google Sheets usando variáveis de ambiente
	err := setupSheetsClient()
	if err != nil {
		log.Fatalf("Erro fatal ao configurar o cliente do Google Sheets: %v", err)
	}
	log.Println("Cliente do Google Sheets configurado com sucesso.")
}

// Configura o serviço do Google Sheets usando a variável de ambiente GOOGLE_CREDENTIALS_JSON
func setupSheetsClient() error {
	ctx := context.Background()
	
	credentialsJSON := os.Getenv("GOOGLE_CREDENTIALS_JSON")
	if credentialsJSON == "" {
		// Isso não deve ocorrer se o Passo 1 foi feito corretamente
		return fmt.Errorf("variável de ambiente GOOGLE_CREDENTIALS_JSON não encontrada. Por favor, configure no Render.")
	}

	config, err := google.JWTConfigFromJSON([]byte(credentialsJSON), sheets.SpreadsheetsScope)
	if err != nil {
		return fmt.Errorf("erro ao configurar JWT: %w", err)
	}

	client := config.Client(ctx)
	
	// Opção para desabilitar o re-uso de token, pode ser útil em ambientes sem refresh_token
	sheetsService, err = sheets.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return fmt.Errorf("erro ao criar o serviço Sheets: %w", err)
	}
	
	return nil
}

// --- Handlers da API ---

// Manipula a importação do XML, parsing e escrita no Sheets.
func importXMLDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido. Use POST.", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	
	var data XMLRequest
	// Limitar o tamanho da leitura do body para evitar abusos (ex: 5MB)
	r.Body = http.MaxBytesReader(w, r.Body, 5*1024*1024) 
	
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		log.Printf("Erro ao decodificar a requisição: %v", err)
		http.Error(w, `{"error": "Requisição JSON inválida ou body muito grande."}`, http.StatusBadRequest)
		return
	}
	
	// Validação básica
	if data.XMLContent == "" {
		http.Error(w, `{"error": "O conteúdo do XML está vazio."}`, http.StatusBadRequest)
		return
	}
	
	spreadsheetID := os.Getenv("SHEET_ID")
	if spreadsheetID == "" {
		log.Println("SHEET_ID não configurado no Render.")
		http.Error(w, `{"error": "Erro de Configuração: SHEET_ID não definido no servidor."}`, http.StatusInternalServerError)
		return
	}
	
	sheetName := "NOTA FISCAL" // Aba padrão
	
	// 1. Processar o XML e preparar os valores para a planilha
	valuesToWrite, chave, err := processXMLAndExtractValues([]byte(data.XMLContent))
	if err != nil {
		log.Printf("Erro ao processar XML: %v", err)
		http.Error(w, fmt.Sprintf(`{"error": "Erro ao processar XML: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}
	
	// 2. Escrever os valores no Google Sheets
	err = writeValuesToSheet(spreadsheetID, sheetName, valuesToWrite)
	if err != nil {
		log.Printf("Erro ao escrever no Google Sheets: %v", err)
		http.Error(w, fmt.Sprintf(`{"error": "Erro ao salvar na planilha: %s. Verifique permissões do Sheets API."}`, err.Error()), http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"message": fmt.Sprintf("Nota Fiscal (Chave: %s) importada com sucesso! %d itens salvos.", chave, len(valuesToWrite)-1),
		"chave": chave,
	}
	json.NewEncoder(w).Encode(response)
}


// --- Lógica de Processamento de XML (Migrada do Fyne) ---

// processXMLAndExtractValues extrai a chave e os itens da NF-e
func processXMLAndExtractValues(xmlBytes []byte) ([][]interface{}, string, error) {
	// A nota fiscal pode estar envelopada com o elemento raiz <nfeProc>
	// Vamos tentar decodificar a <NFe> diretamente ou procurar por ela.

	var nota NFe
	// Tenta decodificar o elemento <NFe> diretamente
	err := xml.Unmarshal(xmlBytes, &nota)
	
	if err != nil {
		// Se falhar, tenta decodificar a partir de um envelope comum (nfeProc)
		type NfeProc struct {
			XMLName xml.Name `xml:"nfeProc"`
			NFe     NFe      `xml:"NFe"`
		}
		var proc NfeProc
		if err = xml.Unmarshal(xmlBytes, &proc); err != nil {
			return nil, "", fmt.Errorf("erro ao decodificar o XML NFe: %w", err)
		}
		nota = proc.NFe
	}


	chave := nota.InfNFe.ID
	if !strings.Contains(chave, "NFe") {
		return nil, "", fmt.Errorf("chave da nota ausente ou inválida")
	}
	// A chave na estrutura XML vem como "NFe4321..."
	chave = strings.TrimPrefix(chave, "NFe")
	
	
	// Contar o número de notas fiscais já existentes para o título (simulação simples)
	// Isso garante que a contagem na planilha continue mesmo após o deploy.
	notasCount, _ := getCurrentNotaCount()

	values := [][]interface{}{}

	// 1. Inserir linha "Xº Nota Fiscal" (Título da Nota)
	notasCount++
	values = append(values, []interface{}{fmt.Sprintf("%dº Nota Fiscal", notasCount)})

	// 2. Inserir itens da NF-e
	for _, det := range nota.InfNFe.Det {
		qtyFloat, _ := strconv.ParseFloat(det.Prod.QCom, 64)
		qtyInt := int(qtyFloat)
		
		// Campos obrigatórios: Nome do Produto (XProd), Quantidade (QCom), Código EAN (CEAN), Item (NItem)
		// Ordem esperada na planilha: XProd, QCom, CEAN, NItem
		values = append(values, []interface{}{det.Prod.XProd, qtyInt, det.Prod.CEAN, det.NItem})
	}
	
	if len(values) <= 1 {
		return nil, "", fmt.Errorf("nenhum item de produto encontrado no XML. Verifique o formato do XML.")
	}

	return values, chave, nil
}

// getCurrentNotaCount simula a contagem de notas na planilha (simplificação)
func getCurrentNotaCount() (int, error) {
	spreadsheetID := os.Getenv("SHEET_ID")
	if spreadsheetID == "" {
		return 0, nil
	}
	
	// Apenas conta quantas vezes "Nota Fiscal" aparece na Coluna A
	readRange := "NOTA FISCAL!A:A"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	resp, err := sheetsService.Spreadsheets.Values.Get(spreadsheetID, readRange).Context(ctx).Do()
	if err != nil {
		log.Printf("Erro ao contar notas na planilha: %v", err)
		return 0, nil 
	}
	
	count := 0
	for _, row := range resp.Values {
		if len(row) > 0 && strings.Contains(fmt.Sprintf("%v", row[0]), "Nota Fiscal") {
			count++
		}
	}
	return count, nil
}

// writeValuesToSheet anexa os valores na planilha
func writeValuesToSheet(spreadsheetID, sheetName string, valuesToWrite [][]interface{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	writeRange := fmt.Sprintf("%s!A:Z", sheetName) // Escreve na coluna A da aba
	
	valueRange := &sheets.ValueRange{
		Values: valuesToWrite,
	}

	_, err := sheetsService.Spreadsheets.Values.Append(spreadsheetID, writeRange, valueRange).
		ValueInputOption("USER_ENTERED").
		InsertDataOption("INSERT_ROWS").
		Context(ctx).
		Do()

	if err != nil {
		return fmt.Errorf("erro ao anexar dados na planilha: %w", err)
	}

	return nil
}

func main() {
	router := http.NewServeMux()
	
	// Novo endpoint para importação de XML
	router.HandleFunc("/import-xml-data", importXMLDataHandler)
	
	// Middleware CORS: CORREÇÃO CRÍTICA
	// Permite que qualquer frontend (como o Canvas) se comunique com este servidor.
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"}, // Permite qualquer origem (Para um ambiente de teste)
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
	})

	handler := c.Handler(router)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // Porta padrão
	}
	log.Printf("Server listening on port %s", port)
	
	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("could not start server: %v", err)
	}
}