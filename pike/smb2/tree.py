import pike.smb2 as smb2


class Tree(object):
    def __init__(self, session, path, smb_res):
        object.__init__(self)
        self.session = session
        self.path = path
        self.tree_id = smb_res.tree_id
        self.tree_connect_response = smb_res[0]
        self.encrypt_data = False
        if smb_res[0].share_flags & smb2.SMB2_SHAREFLAG_ENCRYPT_DATA:
            self.encrypt_data = True
        self.session._trees[self.tree_id] = self
