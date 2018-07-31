//
//  RedAndBlackTree.m
//  算法导论
//
//  Created by 温杰 on 2018/5/21.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "RedAndBlackTree.h"
#import "RBTree.h"
#import "RBTreeRoot.h"
static RBTree  * guard = nil;
void RBinorderTreeWalk(RBTree* node){
    if (node !=guard&& node!=nil) {
        RBinorderTreeWalk(node.left);
        NSLog(@"%d %d",node.value,node.color);
        RBinorderTreeWalk(node.right);
    }
}

@interface RedAndBlackTree()
@property (nonatomic ,strong)RBTreeRoot * root;
@end


@implementation RedAndBlackTree
- (instancetype)init
{
    self = [super init];
    if (self) {
        self.root = [RBTreeRoot new];
        guard = self.root.guard;
    }
    return self;
}

-(void)leftRotate:(RBTree *)x{
    // x 连接 y的 左边
    // x的父类是 y
    //y 的父类是 x的父类
    // 设置是双向的
    RBTree * y = x.right;
    

    if (y==self.root.guard) {
        x.right = self.root.guard;
    }else{
        x.right = y.left;
    }
    y.left.parent = x;
  
    y.parent = x.parent;
    if (x.parent==self.root.guard) {
        self.root.root = y;
    }else if (x == x.parent.left){
        x.parent.left = y;
    }else{
        x.parent.right = y;
    }
    y.left = x;
    x.parent = y;
    
}


-(void)treeInsert:(int)value{
    RBTree * x,*p;
    x = self.root.root;
    p = x;
    while (x!=self.root.guard) {
        if (x!=self.root.guard) {
            if (x.left.color==1 && x.right.color==1) {
                [self rbt_handleReorient:x value:value];
            }
            p = x;
            if (value<x.value) {
                x = x.left;
            }else if (value>x.value){
                x= x.right;
            }else{
                NSLog(@"已经存在 value %d",value);
                return;
            }
        }
    }
    
    x = [RBTree new];

    

    x.value = value;
    x.left = x.right = self.root.guard;
    x.parent = p;
    
    if (self.root.root==self.root.guard) {
        self.root.root = x;
    }else if (value<p.value){
        p.left = x;
    }else{
        p.right = x;
    }
    [self rbt_handleReorient:x value:value];
}

-(void)rbt_handleReorient:(RBTree *)x value:(int)value{
    x.color=1;
    x.left.color = x.right.color = 0;
    if (x.parent.color == 1) {
        x.parent.parent.color = 1;
        ///做节点
        if (x.parent.value<x.parent.parent.value) {
            ///右节点
            if (value>x.parent.value) {
                x.color = 0;
                [self leftRotate:x.parent];
                [self rightRotate:x.parent];
            }else{
                x.parent.color = 0;
                [self rightRotate:x.parent.parent];
            }
        }else{
            if (value<x.parent.value) {
                x.color = 0;
                [self rightRotate:x.parent];
                [self leftRotate:x.parent];
            }else{
                x.parent.color = 0;
                [self leftRotate:x.parent.parent];
            }
        }
    }
    self.root.root.color = 0;
}

///右旋转
-(void)rightRotate:(RBTree *)y
{
    ///叶子节点
    RBTree * x  = y.left;
  
   
    if (x==self.root.guard) {
        y.left = self.root.guard;
    }else{
        y.left = x.right;
    }
    if (self.root.guard!=y.left) {
        y.left.parent = y;
    }
    
    ///处理 y 的 父类指针
    x.parent = y.parent;
    if (x.parent==self.root.guard) {
        self.root.root = x;
    }else if (x == x.parent.left){
        x.parent.left = x;
    }else{
        x.parent.right = x;
    }
    /// 处理 x 的做节点

    ///处理 x的父类
    y.parent = x;
    x.right = y;
}

-(void)rbt_right_rotate:(RBTree *)x{
    RBTree * y = x.left;
    x.left = y.right;
    if (self.root.guard !=x.left) {
        x.left.parent = x;
    }
    
    y.parent = x.parent;
    if (y.parent == self.root.guard) {
        self.root.root = y;
    }else if (y.value <y.parent.value){
        y.parent.left = y;
    }else{
        y.parent.right = y;
    }
    
    y.right = x;
    x.parent = y;
}

-(void)rbt_left_rotate:(RBTree *)x{
    RBTree * y = x.right;
    x.right = y.left;
    if (x.right !=self.root.guard) {
        x.right.parent = x;
    }
    
    y.parent = x.parent;
    if (y.parent ==self.root.guard) {
        self.root.root = y;
    }else if (y.value<y.parent.value){
        y.parent.left = y;
    }else{
        y.parent.right = y;
    }
    
    y.left = x;
    x.parent = y;

}

-(void)RB_treeInsert:(int)value{
    RBTree * y = self.root.guard;
    RBTree * x = self.root.root;
    
    while(x!= self.root.guard) {
        y = x;
        if (value<x.value) {
            x = x.left;
        }else if(value>x.value){
            x = x.right;
        }else{
            NSLog(@"value %d 值已经存在",value);
            return;
        }
    }
    RBTree * z = [RBTree new];
    z.parent = y;
    z.value = value;
    if (y==self.root.guard) {
        self.root.root = z;
    }else if (z.value<y.value){
        y.left = z;
    }else {
        y.right = z;
    }
    
    z.left = self.root.guard;
    z.right = self.root.guard;
    z.color = 1;
    ////这里肯定有问题了。官方代码有问题
     [self RB_treeInsert_Fixup:z];
}

-(void)RB_treeInsert_Fixup:(RBTree *)z{
    RBTree * temp= z;
    ///叔父
     RBTree * y=self.root.guard;
    while (temp.parent.color == 1) {
        ///是否是曾祖父的左边节点
        if (temp.parent==temp.parent.parent.left) {
            ///叔父
            y = temp.parent.parent.right;
            if (y.color == 1) {
                ///父亲变黑 ，
                temp.parent.color = 0;
                ///叔父变黑
                y.color = 0;
                ///祖父变红
                temp.parent.parent.color = 1;
                ///节点移动到祖父
                temp = temp.parent.parent;
            }
           ///要是叔父不是红色的黑色的
            else if (temp==temp.parent.right){
            temp = temp.parent;
            [self leftRotate:temp];
            temp.parent.color = 0;
            temp.parent.parent.color = 1;
                temp = temp.parent.parent;
            [self rightRotate:temp];
                temp = temp.right;
        }else {
            
            temp.parent.color = 0;
            temp.parent.parent.color = 1;
            temp = temp.parent.parent;
            [self rightRotate:temp];
            temp = temp.right;
            
        }
        }else  if (temp.parent==temp.parent.parent.right) {
            ///叔父
            y = temp.parent.parent.left;
            if (y.color == 1) {
                temp.parent.color = 0;
                y.color = 0;
                temp.parent.parent.color = 1;
                temp = temp.parent.parent;
            }
            ///要是叔父不是红色的黑色的
            else if (temp==temp.parent.right){
                temp = temp.parent;
                [self rightRotate:temp];
                temp.parent.color = 0;
                temp.parent.parent.color = 1;
                temp = temp.parent.parent;

                [self leftRotate:temp];
                temp = temp.left;
            }else {
                temp.parent.color = 0;
                temp.parent.parent.color = 1;
                temp = temp.parent.parent;
                [self leftRotate:temp];
                temp = temp.left;
            }
        }
    }
    self.root.root.color = 0;
}

 RBTree* RBtreeSearch(RBTree *node,int value){
    if (node == guard ||node.value == value) {
        return node;
    }
    if (node.value>value) {
        return RBtreeSearch(node.left, value);
    }else{
        return RBtreeSearch(node.right, value);
    }
}

-( RBTree *)tree_minimum:( RBTree *)x{
    while (x.left!=self.root.guard) {
        x = x.left;
    }
    return x;
}

-( RBTree *)tree_maximum:( RBTree *)x{
    while (x.right!=self.root.guard) {
        x=x.right;
    }
    return  x;
}

-( RBTree *)tree_successOr:( RBTree * )x{
    if (x.right!=self.root.guard) {
        return [self tree_minimum:x.right];
    }
    RBTree * y = x.parent;
    ///左儿子是祖先
    while (y!=self.root.guard&&x==y.right) {
        x =y;
        y = y.parent;
    }
    return y;
}
-(void)rb_delete_fixUp:(RBTree *)x{
    //x 是DR
    RBTree * w = self.root.guard;
    ///如果DR 是红色的，直接变为黑色就行了
    
    ///如果DR 是黑色的，那么DR 一定是guard
    while  (x!=self.root.root&& x.color ==0) {
        if (x==x.parent.left) {
            w=x.parent.right;
            ///变成兄弟节点是黑色的了。
            if (w.color == 1) {
                w.color = 0;
                w.parent.color = 1;
                [self leftRotate:x.parent];
                w=x.parent.right;
            }
            
            if (w.left.color==0 &&  w.right.color==0) {
                /// parent 又是新的DR
                w.color = 1;
                x = x.parent;
            }else{
                if (w.right.color==0){
                    w.left.color = 0;
                    w.color = 1;
                    [self rightRotate:w];
                    w = x.parent.right;
                    
                }
                w.color =  x.parent.color ;
                x.parent.color =0;
                w.right.color = 0;
                [self leftRotate:x.parent];
                x = self.root.root;
            }
        }else{
            ///这种情况发生在删除节点只有一个分支的时候并且是右边的分支
            w=x.parent.left;
            ///变成兄弟节点是黑色的了。
            if (w.color == 1) {
                w.color = 0;
                w.parent.color = 1;
                [self rightRotate:x.parent];
                w=x.parent.left;
            }
            
            if (w.left.color==0 &&  w.right.color==0) {
                /// parent 又是新的DR
                w.color = 1;
                x = x.parent;
            }else{
                if (w.left.color==0){
                    w.right.color = 0;
                    w.color = 1;
                    [self leftRotate:w];
                    w = x.parent.left;
                    
                }
                w.color =  x.parent.color ;
                x.parent.color =0;
                w.left.color = 0;
                [self rightRotate:x.parent];
                x = self.root.root;
            }
        }
    }
    
    x.color = 0;
    
}
///a 红色的情况，DR 必定是nil
///b  黑色情况，右边的节点是红色或者黑色
/// b1  DR 是红色 删除d 并且将DR 替换D 改成黑色
/// b2

-(void)rb_delete:(int)value{
    RBTree * y = self.root.guard;
    RBTree * x = self.root.guard;
    RBTree * z =  RBtreeSearch(self.root.root, value);
    if (z == self.root.guard) {
        return;
    }
    if (z.left==self.root.guard||z.right == self.root.guard) {
        y = z;
    }else{
        ///后继
        y = [self tree_successOr:z];
    }
    
    if (y.left!=self.root.guard) {
        x = y.left   ;
    }else{
        x = y.right;
    }
    
    ///红色节点 要不有两个孩子要不有nil
    x.parent = y.parent;
    if (y.parent==self.root.guard) {
        self.root.root = x;
    }else if(y==y.parent.left){
        y.parent.left = x;
    }else{
        y.parent.right = x;
    }
    
    if (y!=z) {
        z.value = y.value;
    }
    ///x是后继节点吗
    if (y.color ==0) {
        [self rb_delete_fixUp:x];
    }
    
    
}

-(void)inorderTreeWalk{
    NSLog(@"root value %d",self.root.root.value);
    RBinorderTreeWalk(self.root.root);
}



@end
