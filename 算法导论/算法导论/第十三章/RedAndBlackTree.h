//
//  RedAndBlackTree.h
//  算法导论
//
//  Created by 温杰 on 2018/5/21.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>
typedef struct RedOrBlockTreeNode{
    struct  RedOrBlockTreeNode * left;
    struct  RedOrBlockTreeNode * right;
    int color;
    struct RedOrBlockTreeNode * parent;
    int value;
}RedOrBlockTreeNode;

@interface RedAndBlackTree : NSObject
-(void)treeInsert:(int)value;

-(void)RB_treeInsert:(int)value;
-(void)inorderTreeWalk;
-(void)rb_delete:(int)value;
@end
