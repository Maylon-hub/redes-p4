class CamadaEnlace:
    ignore_checksum = False

    def __init__(self, linhas_seriais):
        """
        Inicia uma camada de enlace com um ou mais enlaces, cada um conectado
        a uma linha serial distinta. O argumento linhas_seriais é um dicionário
        no formato {ip_outra_ponta: linha_serial}. O ip_outra_ponta é o IP do
        host ou roteador que se encontra na outra ponta do enlace, escrito como
        uma string no formato 'x.y.z.w'. A linha_serial é um objeto da classe
        PTY (vide camadafisica.py) ou de outra classe que implemente os métodos
        registrar_recebedor e enviar.
        """
        self.enlaces = {}
        self.callback = None
        # Constrói um Enlace para cada linha serial
        for ip_outra_ponta, linha_serial in linhas_seriais.items():
            enlace = Enlace(linha_serial)
            self.enlaces[ip_outra_ponta] = enlace
            enlace.registrar_recebedor(self._callback)

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace.
        """
        self.callback = callback

    def enviar(self, datagrama, next_hop):
        """
        Envia datagrama para next_hop, onde next_hop é um endereço IPv4
        fornecido como string (no formato x.y.z.w). A camada de enlace se
        responsabilizará por encontrar em qual enlace se encontra o next_hop.
        """
        # Encontra o Enlace capaz de alcançar next_hop e envia por ele
        if next_hop in self.enlaces:
            self.enlaces[next_hop].enviar(datagrama)

    def _callback(self, datagrama):
        """
        Chama o callback registrado com o datagrama recebido.
        """
        if self.callback:
            self.callback(datagrama)


class Enlace:
    def __init__(self, linha_serial):
        self.linha_serial = linha_serial
        self.linha_serial.registrar_recebedor(self.__raw_recv)
        self.buffer = b''
        self.escapando = False

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de enlace.
        """
        self.callback = callback

    def enviar(self, datagrama):
        # TODO: Preencha aqui com o código para enviar o datagrama pela linha
        # serial, fazendo corretamente a delimitação de quadros e o escape de
        # sequências especiais, de acordo com o protocolo CamadaEnlace (RFC 1055).
        """
        Envia o datagrama pela linha serial, aplicando a delimitação de quadros
        e o escape de sequências especiais, conforme o protocolo CamadaEnlace (RFC 1055).
        """
        # Etapa 2
        # Escapa sequências especiais
        datagrama = datagrama.replace(b'\xdb', b'\xdb\xdd')
        datagrama = datagrama.replace(b'\xc0', b'\xdb\xdc')
        # Etapa 1
        # Adiciona os delimitadores de quadro
        quadro = b'\xc0' + datagrama + b'\xc0'
        
        # Envia o quadro pela linha serial
        self.linha_serial.enviar(quadro)

    def __raw_recv(self, dados):
        """
        Processa os dados recebidos da linha serial, aplicando as regras de
        desescapamento e reconstruindo quadros antes de passá-los para a camada superior.
        """

        # Passo 3
        for byte in dados:
            if byte == 0xC0:
                # Delimitador de fim de quadro
                if self.buffer:
                    # Passo 5
                    try:
                        self.callback(self.buffer)
                    except Exception:
                        import traceback
                        traceback.print_exc()
                    finally:
                        self.buffer = b''
            elif byte == 0xDB:
                # Passo 4
                # Início de sequência de escape
                self.escapando = True
            elif self.escapando:
                # Tratamento de byte escapado
                if byte == 0xDC:
                    self.buffer += b'\xc0'
                elif byte == 0xDD:
                    self.buffer += b'\xdb'
                self.escapando = False
            else:
                # Byte normal, adiciona ao buffer
                self.buffer += bytes([byte])
