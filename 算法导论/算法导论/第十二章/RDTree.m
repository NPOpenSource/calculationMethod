//
//  RDTree.m
//  算法导论
//
//  Created by 温杰 on 2018/5/24.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "RDTree.h"

@implementation RDTree

-(TTree *)ttreeInsert:(int)key{
   TTree * z = [super ttreeInsert:key];
    z.color = 1;
    [self treeInsertFixup:z];
    return z;
}

#define RED 1
#define BLACK 0

-(void)treeInsertFixup:(TTree *)z{
    ///这里是算法导论的算法
#if 1
    while  (z.parent.color==RED) {
        TTree * y = nil;//叔父
        if (z.parent == z.parent.parent.left) {
            y = z.parent.parent.right;
            if (y.color==RED) {
                z.parent.color = BLACK;
                y.color = BLACK;
                z.parent.parent.color = RED;
                z = z.parent.parent;
                
            }else{
                if (z==z.parent.right){///黑色 右节点 结果1
                    z=z.parent;
                    [self leftRoTate:z];
                }
                z.parent.color = BLACK;
                z.parent.parent.color = RED;
                z=z.parent.parent;
                [self rightRotate:z];
                break;
            }
        }else{
            y= z.parent.parent.left;
            if (y.color == RED) {
                z.parent.color = BLACK;
                y.color = BLACK;
                z.parent.parent.color = RED;
                z = z.parent.parent;
            }else{
                if (z ==z.parent.left) {
                    z=z.parent;
                    [self rightRotate:z];
                }
                z.parent.color = BLACK;
                z.parent.parent.color = RED;
                z=z.parent.parent;
                [self leftRoTate:z];
                break;
            }
        }
    }
    self.ttroot.root.color = 0;

#endif
    
/// 分情况比较好理解
#if 0
    while (z.parent.color==1) {
        TTree * y = nil;//叔父
        if (z.parent==z.parent.parent.left) {
            y = z.parent.parent.right;
        }else{
            y = z.parent.parent.left;
        }
        
        ///第一种情况
        if (y.color == 1) {
            z.parent.parent.color = 1;
            z.parent.color = 0;
            y.color =0;
            ///变更结点继续递归循环
            z = z.parent.parent;
        }else if (y.color==0){/// 当儿子和父亲不是一个方向的时候一个左一个右,用p为结点进行旋转
      
            if (z==z.parent.left && z.parent == z.parent.parent.right) {
                z = z.parent;
                [self rightRotate:z];
            }
    
            if (z.parent.right && z.parent==z.parent.parent.left) {
                z=z.parent;
                [self leftRoTate:z];
            }
            
            z.parent.color = 0;
            z.parent.parent.color = 1;
            if (z==z.parent.left && z.parent==z.parent.parent.left) {
                z = z.parent.parent;
                [self rightRotate:z];
                break;
            }
            if (z==z.parent.right && z.parent==z.parent.parent.right) {
                z = z.parent.parent;
                [self leftRoTate:z];
             
                break;
            }
            
        }
    }
    

    self.ttroot.root.color = 0;
    
#endif
}



-(TTree *)delete:(int)key{
    TTree * tree = [super delete:key];
    if (tree.color==0) {
        [self treeDeleteFixup:tree] ;
    }
    return tree;
}

-(void)treeDeleteFixup:(TTree *)z
{
#if 1
    TTree * x = z;
    TTree * w = nil;

    while (x!=self.ttroot.root && x.color == BLACK) {
        if (x ==x.parent.left ) {
            w = x.parent.right;
            if (w.color == RED) {
                w.color=BLACK;
                w.parent.color = RED;
                [self leftRoTate:x.parent];
                w = x.parent.right;
            }
            if (w.left.color == BLACK && w.right.color == BLACK) {
                w.color = RED;
                x = x.parent;
            }else if (w.right.color == BLACK){
                w.left.color = BLACK;
                w.color = RED;
                [self rightRotate:w];
                w = x.parent.right;
            }
            w.color = x.parent.color;
            x.parent.color = BLACK;
            w.right.color = BLACK;
            [self leftRoTate:x.parent];
            return;
        }else{
            w = x.parent.left;

            if (w.color == RED) {
                w.color=BLACK;
                w.parent.color = RED;
                [self rightRotate:x.parent];
                w = x.parent.left;
            }
            if (w.left.color == BLACK && w.right.color == BLACK) {
                w.color = RED;
                x = x.parent;
            }else if (w.left.color == BLACK){
                w.right.color = BLACK;
                w.color = RED;
                [self leftRoTate:w];
                w = x.parent.left;
            }
            w.color = x.parent.color;
            x.parent.color = BLACK;
            w.left.color = BLACK;
            [self rightRotate:x.parent];

        }
    }
    x.color = 0;
#endif
    
    
#if 0
    if (z.left!=nil||z.right!=nil) {
        z.left.color = 0;
        z.right.color = 0;
        return;
    }
    while (z.parent!=nil) {
    ///这样就说明z是没有左右结点的了
    TTree * p = z.parent;
    /// p 肯定有左右儿子
    TTree * s = nil;
    if (z==p.left ||p.left==nil) {
        s = p.right;
    }else{
        s = p.left;
    }
    ///组合一
    if (p.color == 1) {

        if (z==p.left||p.left==nil) {
            if (s.left.color==RED && s.right.color==RED) {
                s.color = RED;
                s.left.color = BLACK;
                s.right.color = BLACK;
                [self leftRoTate:p];
                [self leftRoTate:p];
            }else if(s.left.color == RED){
                [self rightRotate:s];
                s.color = RED;
                s.parent.color = BLACK;
                [self leftRoTate:p];
            }else{
                [self leftRoTate:p];
            }
            
        }else{
            if (s.left.color==RED && s.right.color==RED) {
                s.color = RED;
                s.left.color = BLACK;
                s.right.color = BLACK;
                [self rightRotate:p];
                [self rightRotate:p];
            }else if(s.right.color == RED){
                [self leftRoTate:s];
                s.color = RED;
                s.parent.color = BLACK;
                [self rightRotate:p];
            }else{
                [self rightRotate:p];
            }
        }
        return;
    }

SColorRed:
    ///p是黑色的，那么s是红色的
    if (s.color==1) {
        p.color = 1;
        s.color = 0;
        if (s==p.right) {
            [self leftRoTate:p];
        }else{
            [self rightRotate:p];
        }
        ///s 是红的，SR SL 必定不是nil
        if (p.left!=nil) {
            [self rightRotate:p];
        }else{
            [self leftRoTate:p];
        }
        return;
    }
    
    ///组合三 p 和 s都是 黑的。 那我么只能看SR SL 的颜色了。
    if (s.left.color == 1&& s.right.color == 1) {
        s.left.color = 0;
        s.right.color = 0;
        s.color = 1;
        goto SColorRed;
    }
    
    /// SR SL 只有一个红色
    if (s.left.color == 1) {
        [self rightRotate:s];
        s = s.parent ;
        goto SColorRed;
    }
    if (s.right.color == 1) {
        [self leftRoTate:s];
        s = s.parent;
        goto SColorRed;
    }
    
    s.color = 1;
    z = p;
}
    
#endif
   
}

///中序排列算法
-(void)middleOrderTreeWalk:(TTree*) node{
    if (node !=nil) {
        [self middleOrderTreeWalk:node.left];
        NSLog(@"%d %d",node.key,node.color);
        [self middleOrderTreeWalk:node.right];
    }
}
///前序排列算法
-(void)frontrderTreeWalk:(TTree*) node{
    if (node !=nil) {
        NSLog(@"%d %d",node.key,node.color);
        [self frontrderTreeWalk:node.left];
        [self frontrderTreeWalk:node.right];
    }
}


@end
