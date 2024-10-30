# -*- coding: utf-8 -*-
import re  # Biblioteca para expressões regulares
from burp import IBurpExtender, IHttpListener, IScanIssue  # Importa interfaces do Burp Suite
 
def validate_cpf(cpf):
    # Remove pontos e traço do CPF para validar apenas os dígitos
    cpf = re.sub(r'[.-]', '', cpf)
    # Verifica se todos os dígitos são iguais (11111111111), o que é inválido
    if cpf == cpf[0] * 11:
        return False
 
    # Calcula o primeiro dígito verificador
    sum_ = sum(int(cpf[i]) * (10 - i) for i in range(9))
    digit1 = 11 - (sum_ % 11)
    digit1 = 0 if digit1 >= 10 else digit1
 
    # Calcula o segundo dígito verificador
    sum_ = sum(int(cpf[i]) * (11 - i) for i in range(10))
    digit2 = 11 - (sum_ % 11)
    digit2 = 0 if digit2 >= 10 else digit2
 
    # Verifica se os dígitos calculados correspondem aos últimos dois dígitos fornecidos
    return cpf[-2:] == "{}{}".format(digit1, digit2)
 
class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        # Configuração inicial
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("PII SNIFFER")  # Define o nome da extensão
        callbacks.registerHttpListener(self)  # Registra o listener de HTTP
        print("PII SNIFFER, Installation OK!!!")  # Mensagem de confirmação
 
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Processa a mensagem HTTP
        if not messageIsRequest:  # Verifica se é uma resposta (e não uma solicitação)
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())  # Analisa a resposta
            # Extrai o corpo da resposta
            body_offset = response_info.getBodyOffset()
            body_bytes = messageInfo.getResponse()[body_offset:]
            body = self._helpers.bytesToString(body_bytes)
            # Busca por CPFs com pontos e traço
            cpf_pattern = re.compile(r'\b\d{3}\.\d{3}\.\d{3}-\d{2}\b')
            possible_cpf = cpf_pattern.findall(body)
            possible_cpf = list(set(possible_cpf))  # Remove duplicatas
            cpf_ok = [cpf for cpf in possible_cpf if validate_cpf(cpf)]  # Valida CPFs encontrados
 
            # Busca por números de telefone
            phone_pattern = re.compile(r'\(\d{2}\)\s?\d{4,5}-\d{4}')
            possible_phones = phone_pattern.findall(body)
            possible_phones = list(set(possible_phones))  # Remove duplicatas
 
            # Busca por datas de nascimento
            date_pattern = re.compile(r'\b\d{2}/\d{2}/\d{4}\b')
            possible_dates = date_pattern.findall(body)
            possible_dates = list(set(possible_dates))  # Remove duplicatas
 
            # Busca por números de cartão de crédito
            credit_card_pattern = re.compile(r'\b(?:\d{4}[ -]?){3}\d{4}\b')
            possible_credit_cards = credit_card_pattern.findall(body)
            possible_credit_cards = list(set(possible_credit_cards))  # Remove duplicatas
 
            # Verifica se encontrou algum dado sensível e cria uma issue
            if cpf_ok or possible_phones or possible_dates or possible_credit_cards:
                if cpf_ok:
                    print("CPF: %s" % cpf_ok[0])
                if possible_phones:
                    print("Phone Number(s): %s" % ', '.join(possible_phones))
                if possible_dates:
                    print("Birth Date(s): %s" % ', '.join(possible_dates))
                if possible_credit_cards:
                    print("Credit Card Number(s): %s" % ', '.join(possible_credit_cards))
 
                http_service = messageInfo.getHttpService()
                url = self._helpers.analyzeRequest(messageInfo).getUrl()
                issue_name = "PII data detect"
                issue_detail = "Was found a PII data:"
                if cpf_ok:
                    issue_detail += " CPF: %s" % cpf_ok[0]
                if possible_phones:
                    issue_detail += " Phone Number(s): %s" % ', '.join(possible_phones)
                if possible_dates:
                    issue_detail += " Birth Date(s): %s" % ', '.join(possible_dates)
                if possible_credit_cards:
                    issue_detail += " Credit Card Number(s): %s" % ', '.join(possible_credit_cards)
                severity = "High"
                confidence = "Certain"
                remediation = "Ensure that sensitive information such as CPF, phone numbers, birth dates, and credit card numbers are properly masked or not exposed."
 
                issue = CustomScanIssue(
                    http_service,
                    url,
                    [messageInfo],
                    issue_name,
                    issue_detail,
                    severity,
                    confidence,
                    remediation
                )
                self._callbacks.addScanIssue(issue)
 
class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence, remediation):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._remediation = remediation
 
    def getUrl(self):
        return self._url
 
    def getIssueName(self):
        return self._name
 
    def getIssueType(self):
        return 0
    def getIssueBackground(self):
        return None
 
    def getRemediationBackground(self):
        return None
 
    def getSeverity(self):
        return self._severity
 
    def getConfidence(self):
        return self._confidence
 
    def getIssueDetail(self):
        return self._detail
 
    def getRemediationDetail(self):
        return self._remediation
 
    def getHttpMessages(self):
        return self._http_messages
 
    def getHttpService(self):
        return self._http_service
