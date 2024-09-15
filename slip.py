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

        escaped_bytes = []

        ESCAPE_BYTE = 0xDB
        ESCAPED_DB = 0xDD
        ESCAPED_C0 = 0xDC
        FRAME_DELIMITER = 0xC0

        for byte in datagrama:
            if byte == ESCAPE_BYTE:
                escaped_bytes.append(ESCAPE_BYTE)
                escaped_bytes.append(ESCAPED_DB)
            elif byte == FRAME_DELIMITER:
                escaped_bytes.append(ESCAPE_BYTE)
                escaped_bytes.append(ESCAPED_C0)
            else:
                escaped_bytes.append(byte)

        frame = [FRAME_DELIMITER] + escaped_bytes + [FRAME_DELIMITER]

        self.linha_serial.enviar(bytes(frame))



    def __raw_recv(self, dados):
        # Constants for special bytes
        FRAME_DELIMITER = 0xC0
        ESCAPE_BYTE = 0xDB
        ESCAPED_C0 = 0xDC
        ESCAPED_DB = 0xDD

        # Initialize buffer and escape flag
        for byte in dados:
            if byte == FRAME_DELIMITER:
                self._handle_frame_delimiter()
            elif byte == ESCAPE_BYTE:
                self._start_escape_sequence()
            elif self.escapando:
                self._handle_escape(byte)
            else:
                self._add_to_buffer(byte)




    def _handle_frame_delimiter(self):
        """
        Handles the frame delimiter byte.
        """
        if self.buffer:
            self._process_buffer()
            self.buffer = b''  # Clear the buffer
    
    def _process_buffer(self):
        """
        Processes the buffer by calling the registered callback with the buffer data.
        """ 
        try:
            self.callback(self.buffer)
        except Exception:
            import traceback
            traceback.print_exc()

    def _start_escape_sequence(self):
        """
        Starts the escape sequence processing.
        """
        self.escapando = True

    def _handle_escape(self, byte):
        ESCAPED_C0 = 0xDC
        ESCAPED_DB = 0xDD

        if byte == ESCAPED_C0:
            self.buffer += b'\xc0'
        elif byte == ESCAPED_DB:
            self.buffer += b'\xdb'
        else:
            # If the byte is not part of a valid escape sequence, treat it as regular data
            self.buffer += bytes([ESCAPE_BYTE, byte])
        
        # Reset escaping flag after processing the escape sequence
        self.escapando = False

    def _add_to_buffer(self, byte):
        """
        Adds a regular byte to the buffer.
        """
        self.buffer += bytes([byte])



    

