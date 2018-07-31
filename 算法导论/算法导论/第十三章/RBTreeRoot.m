//
//  RBTreeRoot.m
//  算法导论
//
//  Created by 温杰 on 2018/5/22.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import "RBTreeRoot.h"

@implementation RBTreeRoot
- (instancetype)init
{
    self = [super init];
    if (self) {
        RBTree * tree = [RBTree new];
        self.guard = tree;
        self.root = self.guard;
    }
    return self;
}
@end
