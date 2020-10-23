#!/usr/bin/run python3

'''

A simple program to allow a user to input an IP address and CIDR
and have the network, broadcast, subnetmask and number of hosts calculated.

'''
import tkinter as tk
from tkinter import ttk, END, messagebox


class BoundIntegerEntry(ttk.Entry):
    ''' Entry widget with validation for numeric entry '''

    # Class properties
    max_length = 10
    min_value = 0
    max_value = 9999999999
    tab_keys = None

    def __init__(self, parent, row=0, col=0, width=5, padx=5, state='normal'):
        super().__init__(parent)

        # valid percent substitutions (from the Tk entry man page)
        # note: you only have to register the ones you need; this
        # example registers them all for illustrative purposes
        #
        # %d = Type of action (1=insert, 0=delete, -1 for others)
        # %i = index of char string to be inserted/deleted, or -1
        # %P = value of the entry if the edit is allowed
        # %s = value of entry prior to editing
        # %S = the text string being inserted or deleted, if any
        # %v = the type of validation that is currently set
        # %V = the type of validation that triggered the callback
        #      (key, focusin, focusout, forced)
        # %W = the tk name of the widget

        # Register the validation method
        validation = (self.register(self.validate_entry), '%P', '%s', '%S')

        # Create entry widget and set properties
        self.configure(validate="key",
                       validatecommand=validation,
                       state=state,
                       width=width)
        self.grid(row=row, column=col, padx=padx)

        self.bind('<FocusIn>', self.focus_in)
        self.bind('<FocusOut>', self.focus_out)

    def validate_entry(self, after_valid, before_valid, keyed_value):
        ''' Function will manage data entry validation '''
        # Check for tab_keys
        if (self.tab_keys) and ((len(after_valid) > 1) and (keyed_value in self.tab_keys)):
            self.tk_focusNext().focus()
            return False
        # Check max length
        elif len(after_valid) == self.max_length and keyed_value.isdigit():
            if (self.min_value <= int(after_valid) <= self.max_value):
                self.tk_focusNext().focus()
            else:
                return False
        # Ensure it is digit
        elif not keyed_value.isdigit():
            return False
        return True

    def focus_in(self, event):
        pass

    def focus_out(self, event):
        pass

    def __str__(self):
        return str(self.get())

    def __repr__(self):
        return f'Called: {self.__class__.__name__}'


class OctetEntry(BoundIntegerEntry):
    ''' Octet entry class with validation on key press '''

    # Class property overrides
    max_length = 3
    tab_keys = ['.']
    max_value = 255


class CIDREntry(BoundIntegerEntry):
    ''' CIRD entry class '''

    # Class property overrides
    max_length = 2
    max_value = 32


class IPAddress(ttk.LabelFrame):
    ''' Class to define IP Address of 4 octets '''
    def __init__(self, parent, title='', state='normal'):
        super().__init__(parent)

        # Standard configuration for IP Address frame
        self.configure(text=title,
                       padding=(10, 5, 10, 10))

        # Form layout
        self.octet_1 = OctetEntry(self, row=1, col=0, state=state)
        self.octet_2 = OctetEntry(self, row=1, col=1, state=state)
        self.octet_3 = OctetEntry(self, row=1, col=2, state=state)
        self.octet_4 = OctetEntry(self, row=1, col=3, state=state)

    def valid(self):
        if self.octet_1 and self.octet_1.get().isdigit():
            if self.octet_2 and self.octet_2.get().isdigit():
                if self.octet_3 and self.octet_3.get().isdigit():
                    if self.octet_4 and self.octet_4.get().isdigit():
                        return True
        return False

    def focus_set(self):
        # Set focus to first control
        self.octet_1.focus_set()

    def __str__(self):
        return ('.'.join([str(int(self.octet_1.get())),
                          str(int(self.octet_2.get())),
                          str(int(self.octet_3.get())),
                          str(int(self.octet_4.get()))]))

    def __repr__(self):
        return f'Called: {self.__class__.__name__}'


class CIDRIPAddress(IPAddress):

    ''' Class to define IP Address of 4 octets '''
    def __init__(self, parent, title=''):
        super().__init__(parent, title)

        self.divider_label = tk.Label(self, text='/')
        self.divider_label.grid(row=1, column=4)
        self.cidr = CIDREntry(self, row=1, col=5)

    def valid(self):
        if super().valid() and self.cidr and self.cidr.get().isdigit():
            return True
        return False

    @property
    def ip(self):
        '''
        Returns ip address from the str method of the parent class
        as a property via decorated function
        '''
        return str(self)

    @property
    def netmask(self):
        ''' Returns a subnet mask '''
        netmask = ''
        if self.valid():
            cidr = int(self.cidr.get())
            netmask = self.binary_string_to_ip(("1"*cidr) + ("0"*(32-cidr+1)))
        return netmask

    @property
    def broadcast(self):
        ''' Returns broadcast property via decorated function '''
        broadcast = ''
        if self.valid():
            cidr = int(self.cidr.get())
            assert (0 <= cidr <= 32)
            host_bits = 32-cidr
            ip_bin = list(self.ip_to_binary_string(self.ip))
            broadcast = self.binary_string_to_ip(''.join(ip_bin[:cidr] + \
                                                 list('1'*host_bits)))
        return broadcast

    @property
    def wildcard(self):
        ''' Returns wildcard address via decorated function '''
        wildcard = ''
        if self.valid():
            cidr = int(self.cidr.get())
            host_bits = 32-cidr
            wildcard = self.binary_string_to_ip('0'*cidr + '1'*host_bits)
        return wildcard

    @property
    def hosts(self):
        ''' Returns the number of usable hosts via decorated function '''
        hosts = 0
        if self.valid():
            hosts = int(self.ip_to_binary_string(self.wildcard), 2) + 1
        return hosts

    @property
    def useable_hosts(self):
        ''' Returns the number of usable hosts via decorated function '''
        useable_hosts = 0
        if self.valid():
            if self.hosts <= 2:
                useable_hosts = 0
            else:
                useable_hosts = self.hosts - 2
        return useable_hosts

    @property
    def network(self):
        ''' Returns the network address from the ip_address
            Convert all host bits to 0 for the network address by anding
            with the subnet mask.
        '''
        address = []
        if self.valid():
            ip = self.ip.split('.')
            subnet = self.netmask.split('.')
            for pos in range(4):
                address.append(int(ip[pos]) & int(subnet[pos]))
            network = self.list_to_ip(address)
        return network

    @property
    def first_host(self):
        ''' Returns the first usable host address for the network '''
        first_host = ''
        if self.valid():
            address = self.network.split('.')
            if self.hosts > 2:
                address[3] = str(int(address[3])+1)
            first_host = self.list_to_ip(address)
        return first_host

    @property
    def last_host(self):
        ''' Returns the last usable host address for the network '''
        last_host = ''
        if self.valid():
            address = self.broadcast.split('.')
            if self.hosts > 2:
                address[3] = str(int(address[3])-1)
            last_host = self.list_to_ip(address)
        return last_host

    @property
    def network_cidr(self):
        ''' Returns the network address and cidr '''
        network_cidr = ''
        if self.valid():
            network_cidr = self.network + '/' + self.cidr.get()
        return network_cidr

    @staticmethod
    def ip_to_binary_string(ip):
        ''' Returns the binary of the address '''
        return ''.join([bin(int(octet)+256)[3:] for octet in ip.split('.')])

    @staticmethod
    def list_to_ip(address):
        return ('.'.join([str(octet) for octet in address]))

    @staticmethod
    def binary_string_to_ip(address):
        return '.'.join([str(int(address[0:8], 2)),
                         str(int(address[8:16], 2)),
                         str(int(address[16:24], 2)),
                         str(int(address[24:32], 2))])


class MainFrame(ttk.Frame):
    ''' Main GUI for user to interact with '''
    def __init__(self, parent):
        self.parent = parent
        super().__init__(parent)

        # Form layout
        self.configure(padding=(5, 5))

        self.ip_address = CIDRIPAddress(self, title='IPv4 Address')
        self.ip_address.grid(row=0, column=0, sticky='W')

        self.close = ttk.Button(self, text='Close', command=self.click_close)
        self.close.grid(row=0, column=1, sticky='W')

        self.text = tk.Text(self, width=50, height=15)
        self.text.grid(row=1, column=0, columnspan=2)

        # Set focus
        self.ip_address.focus_set()

        # bind events
        self.ip_address.bind('<FocusIn>', self.ip_entry)
        self.ip_address.bind('<FocusOut>', self.show_summary)

    def ip_entry(self, event):
        self.text.configure(state="normal")

    def show_summary(self, event):
        self.text.delete('1.0', END)

        if self.ip_address.valid():
            self.text.insert(END, 'Address:       ')
            self.text.insert(END, self.ip_address.ip)
            self.text.insert(END, '\n')
            self.text.insert(END, 'Netmask:       ')
            self.text.insert(END, self.ip_address.netmask)
            self.text.insert(END, '\n')
            self.text.insert(END, 'Wildcard:      ')
            self.text.insert(END, self.ip_address.wildcard)
            self.text.insert(END, '\n\n')
            self.text.insert(END, 'Network:       ')
            self.text.insert(END, self.ip_address.network)
            self.text.insert(END, '\n')
            self.text.insert(END, 'First Host:    ')
            self.text.insert(END, self.ip_address.first_host)
            self.text.insert(END, '\n')
            self.text.insert(END, 'Last Host:     ')
            self.text.insert(END, self.ip_address.last_host)
            self.text.insert(END, '\n')
            self.text.insert(END, 'Broadcast:     ')
            self.text.insert(END, self.ip_address.broadcast)
            self.text.insert(END, '\n')
            self.text.insert(END, 'Total Hosts:   ')
            self.text.insert(END, self.ip_address.hosts)
            self.text.insert(END, '\n')
            self.text.insert(END, 'Useable Hosts: ')
            self.text.insert(END, self.ip_address.useable_hosts)
            self.text.insert(END, '\n')
        else:
            self.text.insert(END, 'Enter an IP address and CIDR')
        self.text.configure(state="disabled")

    def click_close(self):
        '''Displays confirmation and if confirmed destroys the form'''
        message_ = "Are you sure you wish to exit?"
        if messagebox.askquestion(self.parent, message_) == "yes":
            self.parent.destroy()

    def __repr__(self):
        return f'Called: {self.__class__.__name__}'


class App(tk.Tk):
    ''' Class to define and setup application '''
    def __init__(self):
        super().__init__()

        # Main application properties
        self.geometry('450x320')
        self.minsize(width=450, height=320)
        self.tk_setPalette(background='#ececec')
        self.title(" IP Network Summary ")

        # Add mainform frame to window
        mf = MainFrame(self)
        mf.pack()

    def __repr__(self):
        return f'Called: {self.__class__.__name__}'


def main():
    ''' Main execution function '''

    # Create application class instance
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
