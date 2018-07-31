//
//  Tree.m
//  算法导论
//
//  Created by 温杰 on 2018/5/18.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "Tree.h"




@interface Tree()

@end

@implementation Tree

- (instancetype)init
{
    self = [super init];
    if (self) {
        self.ttroot = [TTreeRoot new];
        
    }
    return self;
}

-(TTree *)ttreeInsert:(int)key{
    TTree * y = nil;
    TTree * x = self.ttroot.root;
    while (x!=nil) {
        y = x;
        if (key<x.key) {
            x = x.left;
        }else{
            x = x.right;
        }
    }
    TTree * z = [TTree new];
    z.key=key;
    z.parent = y;
    if (y==nil) {
        self.ttroot.root = z;
    }else if (z.key<y.key){
        y.left = z;
    }else{
        y.right = z;
    }
    return z;
}

///中序排列算法
-(void)middleOrderTreeWalk:(TTree*) node{
    if (node !=nil) {
        [self middleOrderTreeWalk:node.left];
        NSLog(@"%d",node.key);
        [self middleOrderTreeWalk:node.right];
    }
}
///前序排列算法
-(void)frontrderTreeWalk:(TTree*) node{
    if (node !=nil) {
        NSLog(@"%d",node.key);
        [self frontrderTreeWalk:node.left];
        [self frontrderTreeWalk:node.right];
    }
}


-(TTree *)searchKey:(int)key rootTree:(TTree*)tree{
    if (tree==nil||tree.key == key) {
        return tree;
    }
    if (key<tree.key) {
       return  [self searchKey:key rootTree:tree.left];
    }else{
        return [self searchKey:key rootTree:tree.right];
    }
    return nil;
}

-(TTree *)ttreeMinimum:(TTree *)tree{
    while (tree.left!=nil) {
        tree = tree.left;
    }
    return tree;
}
-(TTree *)ttreeMaximum:(TTree *)tree;
{
    while (tree.right!=nil) {
        tree = tree.right;
    }
    return tree;
}

///后继
-(TTree *)treeSuccessOr:(TTree *)tree{
    if (tree.right!=nil) {
        return [self ttreeMinimum:tree.right];
    }
    TTree * y = tree.parent;
    while (y!=nil && tree == y.right) {
        tree = y;
        y = y.parent;
    }
    return y;
}

///前趋
-(TTree*)treePredecessOr:(TTree*)tree{
    if (tree.left!=nil) {
        return [self ttreeMaximum:tree.left];
    }
    
    TTree * y = tree.parent;
    while (y!=nil && tree == y.left) {
        tree = y;
        y = y.parent;
    }
    return y;
}

-(TTree * )delete:(int)key{
     TTree *z=  [self searchKey:key rootTree:self.ttroot.root];
    //需要删除的y
    TTree * y=nil;
    TTree * x= nil;

    if (z.left==nil && z.right==nil) {    ///情况1 一个结点没有
        y= z;
        if (y.parent.left==y) {
            y.parent.left = nil;
        }else{
            y.parent.right = nil;
        }
        ///可能是根节点 ///ios 这里可以不关心，因为parent是nil ，给nil赋值还是nil
        if (y.parent==nil) {
            self.ttroot.root = nil;
        }
        
    }else if (z.left==nil ||z.right==nil){ ///情况2  只有一个结点
        y = z;
        if (y.left==nil) {
            x = y.right;
        }else{
            x = y.left;
        }
//
        if (y.parent==nil) {
            y.parent = x;
        }else if (y.parent.left==y) {
            y.parent.left = x;
        }else{
            y.parent.right = x;
        }
    }else{ ///情况3  有两个结点
        ///找到 z的后继结点，将key 赋值给z
         y =[self treeSuccessOr:z];
        z.key = y.key;
        ///再删除 y 就可以了。因为y是后继，没有左结点。y 一定是父类的左结点
        x = y.right;
        ///这里y 可能是根节点。
     if (y.parent.left==y) {
            y.parent.left = x;
        }else{
            y.parent.right = x;
        }
        
    }
    
    return y;
    
# if 0

    if (z.left==nil||z.right==nil) {
        y = z;
    }else{
        y =[self treeSuccessOr:z];
    }
    
    ///我们从三种情况中知道， y只有一个孩子
    if (y.left!=nil) {
        x = y.left;
    }else{
        x = y.right;
    }
    
    if (x!=nil) {
      x.parent = y.parent;
    }
    if (y.parent==nil) {
        self.ttroot.root = x;
    }else if (y.parent.left==y){
        y.parent.left = x;
    }else{
        y.parent.right = x;
    }
    
    if (y!=z) {
        z.key = y.key;
    }
    
    return y;
#endif
}

-(void)leftRoTate:(TTree *)x{
    TTree * y = x.right;
    y.parent = x.parent;
    if (x.parent==nil) {
        self.ttroot.root = y;
    } else if (x.parent.left==x) {
        x.parent.left = y;
    }else{
        x.parent.right = y;
    }
    
    x.right=y.left;
    y.left.parent = x;
    
    x.parent = y;
    y.left = x;
}
-(void)rightRotate:(TTree *)x{
    TTree * y = x.left;
    y.parent = x.parent;
    if (x.parent == nil) {
        self.ttroot.root = y;
    }else if (x.parent.left==x){
        x.parent.left = y;
    }else{
        x.parent.right = y;
    }
    
    x.left = y.right;
    y.right.parent = x;
    
    x.parent = y;
    y.right = x;
    
}


@end
