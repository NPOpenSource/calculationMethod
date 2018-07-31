//
//  RBTree.h
//  算法导论
//
//  Created by 温杰 on 2018/5/22.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RBTree : NSObject
@property (nonatomic,strong) RBTree *left;
@property (nonatomic,strong) RBTree *right;
@property (nonatomic,strong) RBTree *parent;
@property (nonatomic,assign) int color;
@property (nonatomic,assign) int value;

@end
