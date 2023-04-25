/*
 * Copyright 1995, 2022 Perforce Software.  All rights reserved.
 *
 * This file is part of Perforce - the FAST SCM System.
 */

class VarTreeNode;

class VVarTree {

    public:

			VVarTree();
	
	// Derived classes MUST call Clear() in their destructors
	// It cannot be called in the base class, because it calls the pure
	// virtual Delete() method.
	//		~VVarTree() { Clear(); }
	virtual		~VVarTree() {}

	virtual int	Compare( const void *a, const void *b ) const = 0;
	virtual void *	Copy( const void *src ) const = 0;
	virtual void	Delete( void *a ) const = 0;
	virtual void	Dump( void *a, StrBuf &buf ) const = 0;

	void		Clear();
	int		Count() const { return count; }
	void *		Get( const void *keyRecord ) const;
	void *		Put( void *record, Error *e );
	void *		Replace( void *record, Error *e );
	VarTreeNode *	Find( const void *key ) const;

	void *		Shift();
	int		Remove( const void* key );

	VarTreeNode *	FirstNode() const;
	VarTreeNode *	LastNode() const;
	VarTreeNode *	GetNode( const void *keyRecord ) const;
	int		RemoveNode( VarTreeNode* node );

	void		DumpTree();
	void		VerifyTree();

    private:

	friend class VarTreeNode;

	VarTreeNode *	CheckBalance( VarTreeNode* n );
	void		Balance( VarTreeNode* n );

	VarTreeNode*	root;

	int		count;

} ;

class VarTreeNode
{
public:

	void *		Value() const { return k; }

	VarTreeNode *	Next();
	VarTreeNode *	Prev();

private:

	friend class VVarTree;

			VarTreeNode( void *key, VarTreeNode *parent,
			             VVarTree *tree );
			~VarTreeNode();

	void		Dump( int level ) const;

	void *		k;	// key/record

	VarTreeNode *	p;	// parent
	VarTreeNode *	l;	// left child
	VarTreeNode *	r;	// right child

	int		b;	// balance
	int		h;	// height

	VVarTree *	t;
};
