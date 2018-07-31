//
//  TTree.h
//  算法导论
//
//  Created by 温杰 on 2018/5/23.
//  Copyright © 2018年 温杰. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface TTree : NSObject
@property (nonatomic,strong) TTree *left;
@property (nonatomic,strong) TTree *right;
@property (nonatomic,strong) TTree *parent;
@property (nonatomic,assign) int key;
@property (nonatomic,assign) int color;
@end
